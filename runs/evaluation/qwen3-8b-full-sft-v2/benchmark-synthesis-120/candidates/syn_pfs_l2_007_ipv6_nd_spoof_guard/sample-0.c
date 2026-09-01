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
int xdp_filter_syn_pfs_l2_007_ipv6_nd_spoof_guard(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type != ICMPV6_NA)
        return XDP_PASS;

    struct icmp6_na_hdr *na = (void *)icmp;
    if ((void *)(na + 1) > data_end)
        return XDP_PASS;

    __u32 flags = na->flags;
    if ((flags & 0x80000000) && !(flags & 0x40000000))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
