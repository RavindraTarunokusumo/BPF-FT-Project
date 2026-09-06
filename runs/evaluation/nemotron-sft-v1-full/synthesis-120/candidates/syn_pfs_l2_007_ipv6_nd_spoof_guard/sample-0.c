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

struct icmp6_na_hdr {
    __u8  type;
    __u8  code;
    __be16 checksum;
    __be32 reserved;
    __u8  target_ip[16];
};

SEC("xdp")
int xdp_filter_syn_pfs_l2_007_ipv6_nd_spoof_guard(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip6->payload_len;
    if (ip_hdr_len < sizeof(struct icmp6_na_hdr))
        return XDP_PASS;

    struct icmp6_na_hdr *na = (void *)ip6 + sizeof(struct ipv6hdr);
    if ((void *)(na + 1) > data_end)
        return XDP_PASS;

    if (na->type != 136)
        return XDP_PASS;

    __u32 flags = *(__u32 *)(na->target_ip);
    if (((flags & 0x80000000) != 0) && ((flags & 0x40000000) == 0))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
