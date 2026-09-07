#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} route_table_canary SEC(".maps");

SEC("xdp")
int xdp_route_canary(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct lpm_key key;
    key.prefixlen = 32;
    key.data = ip->daddr;

    __u32 *route = bpf_map_lookup_elem(&route_table_canary, &key);
    if (route)
        return XDP_TX;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
