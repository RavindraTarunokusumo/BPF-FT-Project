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

struct grehdr {
    __be32 flags;
    __be32 csum;
};

SEC("xdp")
int xdp_transform_syn_ptr_l2_004_gre_decap_to_inner_ipv4(struct xdp_md *ctx) {
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

    if (ip->protocol != 47)
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > 60)
        return XDP_PASS;

    struct grehdr *gre = (void *)ip + ip_hdr_len;
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    if (gre->flags != 0)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, -24))
        return XDP_PASS;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    eth->h_proto = bpf_htons(ETH_P_IP);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";