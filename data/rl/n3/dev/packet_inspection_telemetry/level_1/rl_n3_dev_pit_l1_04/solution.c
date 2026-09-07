#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} size_hist_4 SEC(".maps");

SEC("xdp")
int xdp_hist_4(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    long len = (long)data_end - (long)data;
    __u32 bin = 0;
    if (len < 128)
        bin = 0;
    else if (len < 512)
        bin = 1;
    else if (len < 1024)
        bin = 2;
    else
        bin = 3;

    __u64 *val = bpf_map_lookup_elem(&size_hist_4, &bin);
    if (val)
        __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
