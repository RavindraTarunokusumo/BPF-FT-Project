#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Set Ethernet destination MAC to broadcast address FF:FF:FF:FF:FF:FF */
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_dest[i] = 0xFF;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
