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

struct gre_hdr {
    __be32 flags;
    __be32 proto;
};

SEC("xdp")
int xdp_transform_syn_ptr_l3_002_gre_encap_push(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, -24) < 0)
        return XDP_PASS;

    struct ethhdr *new_eth = (void *)(long)ctx->data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(new_eth->h_dest, new_eth->h_source, ETH_ALEN);
    new_eth->h_source[0] = 0x52;
    new_eth->h_source[1] = 0x54;
    new_eth->h_source[2] = 0x00;
    new_eth->h_source[3] = 0x99;
    new_eth->h_source[4] = 0x88;
    new_eth->h_source[5] = 0x77;

    struct iphdr *outer_ip = (void *)(new_eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(&outer_ip->saddr, &ip->daddr, sizeof(__u32));
    __builtin_memcpy(&outer_ip->daddr, &ip->saddr, sizeof(__u32));
    outer_ip->protocol = IPPROTO_GRE;
    outer_ip->ttl = 64;

    __u32 csum = 0;
    __u16 *p = (__u16 *)outer_ip;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        csum += p[i];
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    *(__u16 *)p = ~csum;

    struct gre_hdr *gre = (void *)(outer_ip + 1);
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    gre->flags = 0;
    gre->proto = bpf_htons(0x0800);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
