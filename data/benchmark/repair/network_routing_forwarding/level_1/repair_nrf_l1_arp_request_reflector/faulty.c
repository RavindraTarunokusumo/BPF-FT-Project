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

    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        __u8 tmp[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp[i];
        }
        // Behavioral bug: returns XDP_PASS instead of XDP_TX
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
