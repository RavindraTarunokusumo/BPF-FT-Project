#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct flow_timing_5 {
    __u64 first_seen;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct flow_timing_5);
    __uint(max_entries, 1024);
} flow_time_05 SEC(".maps");

SEC("xdp")
int xdp_flow_timing_5(struct xdp_md *ctx) {
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

    struct flow_timing_5 *timing = bpf_map_lookup_elem(&flow_time_05, &src);
    if (timing) {
        timing->last_seen = now;
    } else {
        struct flow_timing_5 init_t = { .first_seen = now, .last_seen = now };
        bpf_map_update_elem(&flow_time_05, &src, &init_t, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
