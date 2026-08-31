#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;

    if (bpf_xdp_adjust_head(ctx, -20))
        return XDP_DROP;

    // Verifier error: pointers not refreshed from ctx->data
    eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
