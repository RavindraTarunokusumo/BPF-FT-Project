#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 5-tuple flow key */
struct flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8   proto;
};

/* LRU hash map indexed by flow_key, value is __u64 packet counter */
struct {
    __uint	type, BPF_MAP_TYPE_LRU_HASH;
    __uint	key_size, sizeof(struct flow_key);
    __uint	value_size, sizeof(__u64);
    __uint(max_entries, 65536);
} flow_table_04 SEC(".maps");

SEC("xdp")
int xdp_flow_counter_04(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify IPv4 protocol */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Verify transport layer presence */
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Verify transport header bounds */
    void *transport = (void *)(ip + 1);
    /* IPv4 header length in 32-bit words, ihl is min 5 (20 bytes) */
    int ihl = ip->ihl * 4;
    if (ihl < 20 || (void *)(transport + 1) > data_end)
        return XDP_PASS;

    /* Extract 5-tuple fields */
    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = *(__be16 *)transport,
        .dport = *(__be16 *)((void *)transport + sizeof(__be16)),
        .proto = ip->protocol,
    };

    /* Atomically increment packet counter in the LRU hash map */
    __u64 *counter = bpf_map_lookup_elem(flow_table_04, &key);
    if (counter) {
        (*counter)++;
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(flow_table_04, &key, &init_val, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
