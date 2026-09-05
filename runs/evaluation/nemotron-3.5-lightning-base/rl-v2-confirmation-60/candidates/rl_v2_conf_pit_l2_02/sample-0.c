#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Define the 5-tuple key structure */
struct flow_key {
    __be32 saddr;      /* source IP address */
    __be32 daddr;      /* destination IP address */
    __be16 sport;      /* source port */
    __be16 dport;      /* destination port */
    __u8   proto;      /* protocol (IPPROTO_TCP or IPPROTO_UDP) */
};

/* Define the LRU hash map */
struct {
    __uint	type,		BPF_MAP_TYPE_LRU_HASH;
    __uint	key_size,		sizeof(struct flow_key);
    __uint	value_size,	sizeof(__u64);
    __uint	max_entries,	65536;
} flow_table_02 SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_flow_monitor(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic (AF_INET) */
    if (ip->version != 4)
        return XDP_PASS;

    /* Verify transport header bounds based on protocol */
    __u8 proto = ip->protocol;
    void *l4_start = (void *)(ip + 1);

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_start;
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
            return XDP_PASS;
        /* TCP processing - key populated below */
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4_start;
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
            return XDP_PASS;
        /* UDP processing - key populated below */
    } else {
        /* Non-TCP/UDP protocols: still populate key with proto field,
           but only if transport header fits within bounds */
        if (data + sizeof(*eth) + sizeof(*ip) + 1 > data_end)
            return XDP_PASS;
    }

    /* Populate the 5-tuple key */
    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = 0,   /* Will be filled from L4 header if available */
        .dport = 0,
        .proto   = proto
    };

    /* Extract L4 ports if protocol matches and header is valid */
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_start;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4_start;
        key.sport = udp->source;
        key.dport = udp->dest;
    }

    /* Atomically increment packet count in the flow map */
    __u64 *val, one = 1;
    val = bpf_map_lookup_elem(flow_table_02, &key);
    if (val) {
        *val = bpf_atomic_add(one, val);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(flow_table_02, &key, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
