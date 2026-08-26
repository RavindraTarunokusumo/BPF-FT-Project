#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_small(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 len = (long)data_end - (long)data;
    if (len < 64)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
