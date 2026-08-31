#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} byte_count SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 len = (__u64)data_end - (__u64)data;

    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&byte_count, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, len);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
