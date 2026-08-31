#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} byte_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if ((void *)(data + 1) > data_end)
        return XDP_PASS;

    __u8 first_byte = *(__u8 *)data;
    __u32 key = first_byte & 15;

    __u64 *cnt = bpf_map_lookup_elem(&byte_hist, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
