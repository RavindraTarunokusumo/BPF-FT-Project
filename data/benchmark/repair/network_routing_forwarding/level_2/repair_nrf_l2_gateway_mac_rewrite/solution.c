#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u8 nexthop_mac[ETH_ALEN] = {0x52, 0x54, 0x00, 0x11, 0x22, 0x33};
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_dest[i] = nexthop_mac[i];
    }

    return bpf_redirect(2, 0);
}

char LICENSE[] SEC("license") = "GPL";
