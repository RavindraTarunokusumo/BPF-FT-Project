#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct ip_pair {
    __u32 saddr;
    __u32 daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ip_pair);
    __type(value, __u64);
    __uint(max_entries, 1024);
} ip_pair_map SEC(".maps");

SEC("xdp")
int xdp_filter_pair(struct xdp_md *ctx) {
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

    struct ip_pair key = { .saddr = ip->saddr, .daddr = ip->daddr };
    __u64 *count = bpf_map_lookup_elem(&ip_pair_map, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
        if (*count > 50)
            return XDP_DROP;
    } else {
        __u64 init_c = 1;
        bpf_map_update_elem(&ip_pair_map, &key, &init_c, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
