#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_route_sub_12(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 mask = bpf_htonl(0xFFFF0000);
    __u32 target = bpf_htonl((10 << 24) | (22 << 16));

    if ((ip->daddr & mask) == target) {
        eth->h_dest[0] = 0x52;
        eth->h_dest[1] = 0x54;
        eth->h_dest[2] = 0x00;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x01;
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
