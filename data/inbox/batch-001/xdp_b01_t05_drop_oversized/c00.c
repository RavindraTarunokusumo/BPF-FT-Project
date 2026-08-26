#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_oversized(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    unsigned long pkt_len = (unsigned long)((char *)data_end - (char *)data);
    if (pkt_len > 1400)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
