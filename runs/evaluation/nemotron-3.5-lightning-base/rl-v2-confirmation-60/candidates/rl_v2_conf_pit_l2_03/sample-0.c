#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* 5-tuple flow key */
struct flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8   proto;
};

/* LRU Hash map: key = struct flow_key, value = __u64 packet counter */
struct {
    __uint	type, BPF_MAP_TYPE_LRU_HASH;
    __uint	key_size, sizeof(struct flow_key);
    __uint	value_size, sizeof(__u64);
    __uint	max_entries, 65536;
} flow_table_03 SEC(".maps");

SEC("xdp")
int xdp_flow_telemetry(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 payload */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify L4 transport header exists and has enough room for key fields */
    /* We need at least sport (2) + dport (2) after the IP header.
       proto is already in ip->protocol. */
    void *l4 = data + sizeof(*eth) + sizeof(*ip);
    if (l4 + sizeof(__be16) * 2 > data_end)
        return XDP_PASS;

    /* Build the 5-tuple key */
    struct flow_key key = {
        .saddr    = ip->saddr,
        .daddr    = ip->daddr,
        .sport    = *(__be16 *)(l4),
        .dport    = *(__be16 *)(l4 + sizeof(__be16)),
        .proto    = ip->protocol,
    };

    /* Atomically increment the per-flow packet counter */
    __u64 *val, one = 1;
    val = bpf_map_lookup_elem(&flow_table_03, &key);
    if (val) {
        *val = bpf_atomic_add(one, val);
    } else {
        /* Insert with initial count of 1 if not present */
        bpf_map_update_elem(&flow_table_03, &key, &one, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
