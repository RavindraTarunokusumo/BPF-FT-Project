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

struct srv6_hdr {
    __u8  next_hdr;
    __u8  routing_type;
    __u16 segments_left;
    __u32 seg_1;
    __u32 seg_2;
    __u32 seg_3;
    __u32 seg_4;
};

SEC("xdp")
int xdp_syn_nrf_l3_004_srv6_to_gtpu_translation_router(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6_hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    if (ip6->nexthdr != 43)
        return XDP_PASS;

    struct srv6_hdr *srh = (void *)(ip6 + 1);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;

    if (srh->routing_type != 4)
        return XDP_PASS;

    __u32 active_sid = srh->seg_1;
    if (active_sid == bpf_htons(0xFFFF2001)) {
        // 2001:db8:ffff::/48 check
        __u32 sid_upper = srh->seg_2;
        if ((sid_upper & bpf_htons(0xFFFF0000)) == bpf_htons(0xFFFF0000)) {
            return bpf_redirect(60, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
