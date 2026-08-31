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
int xdp_spoof_guard_pfs_l2_007(struct xdp_md *ctx) {
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

    if (ip6->nexthdr != IPPROTO_ICMPV6)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip6->hdr_len;
    if (ip_hdr_len < sizeof(struct ipv6hdr))
        return XDP_PASS;

    if ((void *)ip6 + ip_hdr_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip6 + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type != ICMPV6_NA)
        return XDP_PASS;

    unsigned int icmp_hdr_len = icmp->icmp_hdr_len;
    if (icmp_hdr_len < sizeof(struct icmp6_na_hdr))
        return XDP_PASS;

    if ((void *)icmp + icmp_hdr_len > data_end)
        return XDP_PASS;

    struct icmp6_na_hdr *na = (void *)icmp;
    __u32 flags = na->flags;

    if ((flags & 0x80000000) && !(flags & 0x40000000))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
