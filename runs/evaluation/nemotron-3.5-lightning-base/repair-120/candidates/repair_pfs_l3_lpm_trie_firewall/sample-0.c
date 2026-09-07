#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * LPM Trie Key definition.
 * BPF_MAP_TYPE_LPM_TRIE requires the key to start with a __u32 prefixlen field.
 * The 'data' field holds the actual IP address (saddr).
 */
struct lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_blocklist SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    // Check if Ethernet header fits
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check for IPv4 protocol
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    // Check if IP header fits
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Initialize LPM key:
    // 1. Set prefixlen to 32 for exact source IP match.
    // 2. Set data to the source IP address from the IP header.
    struct lpm_key key = {
        .prefixlen = 32,
        .data = ip->saddr,
    };

    __u32 *val = bpf_map_lookup_elem(&lpm_blocklist, &key);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
