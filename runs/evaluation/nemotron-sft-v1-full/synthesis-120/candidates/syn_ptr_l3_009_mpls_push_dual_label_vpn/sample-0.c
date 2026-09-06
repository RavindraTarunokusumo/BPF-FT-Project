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

struct mpls_hdr {
    __u32 label:20;
    __u32 exp:3;
    __u32 bos:1;
};

SEC("xdp")
int xdp_transform_syn_ptr_l3_009_mpls_push_dual_label_vpn(struct xdp_md *ctx) {
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

    unsigned char *new_head = (void *)ip - 8;
    if ((void *)new_head < data)
        return XDP_DROP;

    if (bpf_xdp_adjust_head(ctx, -8))
        return XDP_DROP;

    struct ethhdr *new_eth = (void *)ctx->data;
    __builtin_memcpy(new_eth->h_dest, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(new_eth->h_source, eth->h_source, ETH_ALEN);
    new_eth->h_proto = bpf_htons(0x8847);

    struct mpls_hdr *labels = (void *)(new_eth + 1);
    if ((void *)(labels + 2) > data_end)
        return XDP_PASS;

    labels[0].label = bpf_htons(1000);
    labels[0].exp = 0;
    labels[0].bos = 0;

    labels[1].label = bpf_htons(200);
    labels[1].exp = 0;
    labels[1].bos = 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
