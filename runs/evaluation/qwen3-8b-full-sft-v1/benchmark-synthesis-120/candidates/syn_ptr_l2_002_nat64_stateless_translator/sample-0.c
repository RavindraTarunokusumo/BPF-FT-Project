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
int xdp_transform_syn_ptr_l2_002_nat64_stateless_translator(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    __u8 *d = (void *)&ip6->daddr;
    if (d[0] != 0x64 || d[1] != 0xff || d[2] != 0x9b ||
        (d[3] & 0xff000000) != 0)
        return XDP_PASS;

    __u32 *p = (__u32 *)d + 3;
    __u32 new_d = *p;

    __u64 new_hdr = (unsigned long)ip6 - 20;
    if (new_hdr < (unsigned long)data)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, -20))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    ip6 = data + sizeof(struct ethhdr) + sizeof(struct iphdr) - sizeof(struct ipv6hdr);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip4 = data + sizeof(struct ethhdr);
    if ((void *)(ip4 + 1) > data_end)
        return XDP_PASS;

    ip4->ihl = 5;
    ip4->ttl = 64;
    ip4->protocol = eth->h_proto;
    ip4->check = 0;
    ip4->saddr = ip6->saddr;
    ip4->daddr = (__u32)ip6->daddr + (new_d & 0x00FFFFFF);

    __u16 *c = (__u16 *)ip4 + sizeof(struct iphdr)/2;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        c[i] += 0x1234;

    ip4->check = (__u32)c[0] + (__u32)c[1] + (__u32)c[2] + (__u32)c[3] + (__u32)c[4] + (__u32)c[5] + (__u32)c[6] + (__u32)c[7] + (__u32)c[8] + (__u32)c[9];
    ip4->check = (ip4->check & 0xFFFF) + (ip4->check >> 16);

    ip6 = (void *)(ip4 + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    ip6->nh_len = sizeof(struct ipv6hdr) - sizeof(struct iphdr);
    ip6->hlim = 64;
    ip6->proto = IPPROTO_UDP;
    ip6->daddr = ip4->daddr;
    ip6->saddr = ip4->saddr;
    ip6->flow_lbl[0] = 0x64FF;
    ip6->flow_lbl[1] = 0x9B00;
    ip6->flow_lbl[2] = 0x0000;
    ip6->payload_len = (__u32)ip6 + sizeof(struct ipv6hdr) - (__u32)data;
    ip6->priority = 0x80;
    ip6->nexthdr = IPPROTO_UDP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
