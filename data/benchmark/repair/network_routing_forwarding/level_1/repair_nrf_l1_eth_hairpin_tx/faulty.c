#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Verifier error: missing (eth + 1 <= data_end) check before dereferencing eth
    __u8 tmp[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp[i];
    }

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
