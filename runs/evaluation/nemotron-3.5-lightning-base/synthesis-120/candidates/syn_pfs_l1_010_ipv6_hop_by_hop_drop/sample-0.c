#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>

/* XDP program entry point */
SEC("xdp")
int xdp_syn_pfs_l1_010_ipv6_hop_by_hop_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Validate Ethernet header bounds and check EtherType */
    struct eth_hdr *eth;
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    /* 2. Validate 40-byte IPv6 header bounds */
    struct ipv6hdr *ip6;
    ip6 = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    /* 3. Check nexthdr field: 0 means Hop-by-Hop Options (IPPROTO_HOPOPTS) */
    if (ip6->nexthdr == 0)
        return XDP_DROP;

    /* 4. Pass all other traffic: standard IPv6 (TCP/UDP/ICMPv6), IPv4, malformed frames */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
