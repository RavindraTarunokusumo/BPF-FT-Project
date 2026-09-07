#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter_runt(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    long len = (long)data_end - (long)data;
    if (len < 40)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
