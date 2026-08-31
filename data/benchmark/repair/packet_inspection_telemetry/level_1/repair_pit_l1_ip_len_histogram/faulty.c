#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} len_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u64 len = (__u64)(long)ctx->data_end - (__u64)(long)ctx->data;
    __u32 bucket; // Verifier error: uninitialized stack variable on some branches

    if (len < 64)
        bucket = 0;
    else if (len < 128)
        bucket = 1;
    else if (len < 512)
        bucket = 2;
    else if (len >= 512)
        bucket = 3;

    // If len was negative or NaN (theoretically), bucket is uninitialized
    __u64 *cnt = bpf_map_lookup_elem(&len_hist, &bucket);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
