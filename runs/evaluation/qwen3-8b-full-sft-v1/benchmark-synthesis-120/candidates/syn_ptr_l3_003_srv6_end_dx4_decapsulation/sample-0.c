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
int xdp_transform_syn_ptr_l3_003_srv6_end_dx4_decapsulation(struct xdp_md *ctx) {
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

    if (ip6->nexthdr != IPPROTO_SCTP)
        return XDP_PASS;

    struct sctphdr *sctp = (void *)(ip6 + 1);
    if ((void *)(sctp + 1) > data_end)
        return XDP_PASS;

    if (sctp->check != 0x12345678)
        return XDP_PASS;

    __u64 pkt_len = (__u64)data + sizeof(struct xdp_md);
    if (pkt_len < (void *)ip6 + sizeof(struct ipv6hdr))
        return XDP_PASS;

    // Adjust head to remove outer IPv6 + SRH headers
    __u64 new_hdr = (__u64)ip6 + sizeof(struct ipv6hdr) + sizeof(struct srh_hdr);
    if (new_hdr < (__u64)data)
        return XDP_PASS;
    
    if (new_hdr + sizeof(struct ethhdr) > pkt_len)
        return XDP_PASS;

    __builtin_memcpy(eth, data, sizeof(struct ethhdr));
    ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > (void *)data + pkt_len - new_hdr)
        return XDP_PASS;

    ip6->protocol = IPPROTO_TCP;
    ip6->nexthdr = IPPROTO_TCP;
    ip6->hop_limit = 64;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
