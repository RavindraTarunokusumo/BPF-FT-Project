#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} burst_timestamp_map SEC(".maps");

SEC("xdp")
int xdp_filter_burst(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&burst_timestamp_map, &src);
    if (last) {
        if (now - *last < 1000000ULL)
            return XDP_DROP;
        *last = now;
    } else {
        bpf_map_update_elem(&burst_timestamp_map, &src, &now, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
