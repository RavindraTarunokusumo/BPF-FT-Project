#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Define the 5-tuple flow key */
struct flow_key {
    __be32 saddr;      /* source IP address */
    __be32 daddr;      /* destination IP address */
    __be16 sport;      /* source port */
    __be16 dport;      /* destination port */
    __u8   proto;      /* protocol (IPPROTO_TCP, IPPROTO_UDP, etc.) */
};

/* LRU hash map to track flow sessions */
struct {
    __uint	type,		BPF_MAP_TYPE_LRU_HASH;
    __uint	key_size,		sizeof(struct flow_key);
    __uint	value_size,	sizeof(__u64);
    __uint	max_entries,	65536;
} flow_table_01 SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_flow_tracker(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only support TCP and UDP transport protocols */
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Verify L4 transport header bounds */
    /* Transport header starts right after the IPv4 header */
    void *l4_start = data + sizeof(*eth) + sizeof(*ip);
    struct tcphdr *tcp;
    struct udphdr *udp;

    if (ip->protocol == IPPROTO_TCP) {
        if (l4_start + sizeof(*tcp) > data_end)
            return XDP_PASS;
        tcp = l4_start;
        /* Ensure TCP header does not exceed the advertised data offset */
        if (tcp->doff * 4 < sizeof(*tcp) || l4_start + tcp->doff * 4 > data_end)
            return XDP_PASS;
    } else { /* IPPROTO_UDP */
        if (l4_start + sizeof(*udp) > data_end)
            return XDP_PASS;
    }

    /* Populate the 5-tuple flow key */
    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = ((struct tcphdr *)l4_start)->source,
        .dport = ((struct tcphdr *)l4_start)->dest,
        .proto = ip->protocol
    };

    /* Atomically increment the packet counter for this flow */
    __u64 *val, one = 1;
    val = bpf_map_lookup_elem(&flow_table_01, &key);
    if (val) {
        (*val)++;
    } else {
        /* Insert with initial count of 1 if not present */
        bpf_map_update_elem(&flow_table_01, &key, &one, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
