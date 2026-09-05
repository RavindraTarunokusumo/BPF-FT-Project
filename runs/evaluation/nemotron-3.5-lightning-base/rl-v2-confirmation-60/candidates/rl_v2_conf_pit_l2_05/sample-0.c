#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* 5-tuple flow key */
struct flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8   proto;
};

/* XDP program entry point */
SEC("xdp")
int xdp_flow_count(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify transport header based on protocol */
    void *l4 = (void *)(ip + 1);
    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .proto = ip->protocol,
    };

    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = l4;
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp = l4;
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
        key.dport = udp->dest;
        break;
    }
    default:
        /* For other protocols (e.g., ICMP), sport/dport are undefined;
         * zero-fill the remaining key fields to keep the map lookup valid. */
        key.sport = 0;
        key.dport = 0;
        break;
    }

    /* Atomically increment the per-session packet counter */
    __u64 *val = bpf_map_lookup_elem(flow_table_05, &key);
    if (val) {
        (*val)++;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(flow_table_05, &key, &BPF_ANY, &init, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
