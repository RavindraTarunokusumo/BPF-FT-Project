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

    if (eth->h_proto != bpf_htons(0x86DD))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    if (ip6->nexthdr != IPPROTO_UDP)
        return XDP_PASS;

    __u8 *d = (void *)&ip6->daddr;
    if (d[0] != 0x64 || d[1] != 0xff || d[2] != 0x9b || d[3] != 0x00 ||
        d[4] != 0x00 || d[5] != 0x00 || d[6] != 0x00 || d[7] != 0x00)
        return XDP_PASS;

    __u32 new_d = (bpf_ntohl(*(__u32 *)d) & 0x00FFFFFF) | 0xC0A80000;
    __u8 *new_d_ptr = (void *)&new_d;

    int res = bpf_xdp_adjust_head(ctx, -20);
    if (res < 0)
        return XDP_PASS;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    __u16 csum = bpf_csum_diff(0, 0, 20, (__u32)ip);
    ip->check = (__u16)csum ^ 0xFFFF;

    ip->daddr = bpf_htons((__u16)new_d_ptr[2] << 16 | (__u16)new_d_ptr[3] << 8 | (__u16)new_d_ptr[4]);
    eth->h_proto = bpf_htons(0x0800);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";