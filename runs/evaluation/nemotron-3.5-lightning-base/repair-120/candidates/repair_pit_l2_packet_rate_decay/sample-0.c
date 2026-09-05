#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct rate_val {
    __u64 last_ts;
    __u64 rate_acc;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct rate_val);
    __uint(max_entries, 1);
} rate_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u32 key = 0;
    struct rate_val *val = bpf_map_lookup_elem(&rate_stats, &key);
    if (!val)
        return XDP_PASS;

    if (val->last_ts != 0) {
        __u64 delta = now - val->last_ts;
        // Bit-shift approximation for decay factor.
        // Using shift right by 30 (divide by 2^30 ~ 1.07e9) to approximate
        // the normalization factor previously handled by 64-bit division.
        __u64 decay_factor = (delta > 0) ? (delta >> 30) : 1;
        // Apply decay using bit-shift instead of division.
        // Equivalent to: val->rate_acc = val->rate_acc / (decay_factor + 1) + 1;
        // Using shift to approximate the division operation.
        val->rate_acc = (val->rate_acc >> 3) + 1; 
    } else {
        val->rate_acc = 1;
    }
    val->last_ts = now;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
