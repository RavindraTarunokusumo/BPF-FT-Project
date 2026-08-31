#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u8 new_src[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x42};
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_source[i] = new_src[i];
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
