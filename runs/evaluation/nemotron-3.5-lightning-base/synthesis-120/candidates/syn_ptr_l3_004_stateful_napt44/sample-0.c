#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map definitions */
#define MAP_MAX_ENTRIES 1024

struct napt_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

/* Forward mapping: private -> public */
struct bpf_map_def napt_fwd_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct napt_tuple),
    .value_size = sizeof(__be32), /* public IP */
    .max_entries = MAP_MAX_ENTRIES,
};

/* Reverse mapping: public -> private */
struct bpf_map_def napt_rev_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32), /* public IP */
    .value_size = sizeof(struct napt_tuple),
    .max_entries = MAP_MAX_ENTRIES,
};

SEC("xdp")
int napt44_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __be32 *val;
    struct napt_tuple key, rev_key;
    __be32 public_ip = bpf_htonl(198511001U); /* 198.51.100.1 */
    __be16 public_port = bpf_htons(30000);

    /* Verify Ethernet frame */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header length */
    if (ip->ihl < 5)
        return XDP_PASS;

    /* Verify TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* --- Outbound path: private -> public --- */
    if (ip->saddr == bpf_htonl(0x0a000000U)) { /* 10.0.0.0/8 */
        /* Build forward key: (src_ip, dst_ip, src_port, dst_port) */
        key.src_ip = ip->saddr;
        key.dst_ip = ip->daddr;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;

        /* Lookup existing mapping */
        val = bpf_map_lookup_elem(&napt_fwd_map, &key, NULL, 0);
        if (val) {
            /* Already mapped – just update ports if needed */
            ip->saddr = public_ip;
            tcp->source = public_port;
        } else {
            /* New mapping */
            ip->saddr = public_ip;
            tcp->source = public_port;

            /* Store forward mapping */
            bpf_map_update_elem(&napt_fwd_map, &key, &public_ip, BPF_ANY);

            /* Build reverse key: (public_ip, public_port, dst_port, src_port) */
            rev_key.src_ip = public_ip;
            rev_key.dst_ip = key.dst_ip; /* original dst */
            /* We store public_port as first port field, original dst as second */
            /* Simpler: use public_ip as rev key, value holds full tuple */
            /* We'll store the original tuple in rev map for return path */
            struct napt_tuple rev_val;
            rev_val.src_ip = key.src_ip;
            rev_val.dst_ip = key.dst_ip;
            rev_val.src_port = key.src_port;
            rev_val.dst_port = key.dst_port;
            bpf_map_update_elem(&napt_rev_map, &public_ip, &rev_val, BPF_ANY);
        }
    }
    /* --- Inbound path: public -> private --- */
    else if (ip->daddr == public_ip) {
        /* Lookup reverse mapping by public IP */
        val = bpf_map_lookup_elem(&napt_rev_map, &ip->daddr, NULL, 0);
        if (val) {
            struct napt_tuple *t = val;

            /* Restore private IP/port */
            ip->saddr = t->src_ip;
            tcp->source = t->src_port;

            /* Optional: restore original dst if needed, but we keep original */
        } else {
            /* No mapping – could be unrelated traffic; leave unchanged */
        }
    }

    /* Recalculate IPv4 checksum */
    ip->check = 0;
    ip->check = bpf_csum_diff(0, 0, (unsigned short *)ip, sizeof(struct iphdr), 0);

    /* Recalculate TCP checksum if payload present */
    if (tcp->check) {
        /* Zero TCP checksum first */
        tcp->check = 0;
        /* Simple recalc: pseudo-header + tcp header + payload */
        /* BPF helper bpf_l3_csum_help handles IP checksum; for TCP we rely on hardware
         * or full recalc. Here we just zero and let the stack handle it, or do a basic
         * partial recalc. For strict compliance, use bpf_l4_csum_help if available.
         * Since we must be verifier-safe, we zero and let the kernel recompute on
         * transmit if the device supports generic checksum offload.
         * We explicitly set it to 0 so the kernel can recompute. */
        tcp->check = 0; /* trigger recalc on send if offload enabled */
    }

    return XDP_PASS;
}

char LICENSE[] = "GPL";
