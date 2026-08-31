#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Behavioral bug: 0xAC100000 in host order compared against raw network order ip->daddr
    if ((ip->daddr & 0xFFFF0000) == 0xAC100000) {
        __u8 tmp[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp[i];
        }
        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
