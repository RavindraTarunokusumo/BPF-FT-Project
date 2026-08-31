#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

struct icmp6_na_hdr {
    struct icmp6hdr icmp6;
    __u32 flags_reserved; // R (bit 31), S (bit 30), O (bit 29)
    struct in6_addr target_addr;
};

SEC("xdp")
int xdp_nd_spoof_guard(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    struct icmp6_na_hdr *na = (void *)(ip6 + 1);
    if ((void *)(na + 1) > data_end)
        return XDP_PASS;

    if (na->icmp6.icmp6_type != 136) // 136 = Neighbor Advertisement
        return XDP_PASS;

    __u32 flags = bpf_ntohl(na->flags_reserved);
    int r_bit = (flags & 0x80000000) != 0; // Router flag
    int s_bit = (flags & 0x40000000) != 0; // Solicited flag

    // Drop unsolicited Neighbor Advertisements claiming to be a Router (R=1, S=0)
    if (r_bit && !s_bit)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
