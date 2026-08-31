#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

struct srv6_hdr {
    __u8 nexthdr;
    __u8 hdr_ext_len;
    __u8 routing_type;
    __u8 segments_left;
    __u8 last_entry;
    __u8 flags;
    __u16 tag;
};

SEC("xdp")
int xdp_srv6_gtpu_router(struct xdp_md *ctx) {
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
    if (ip6->nexthdr != 43)
        return XDP_PASS;

    struct srv6_hdr *srh = (void *)(ip6 + 1);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;
    if (srh->routing_type != 4)
        return XDP_PASS;

    __u16 *sid_words = (void *)(srh + 1);
    if ((void *)(sid_words + 8) > data_end)
        return XDP_PASS;

    // Check 2001:db8:ffff::/48 (0x2001, 0x0db8, 0xffff)
    if (sid_words[0] == bpf_htons(0x2001) && sid_words[1] == bpf_htons(0x0DB8) && sid_words[2] == bpf_htons(0xFFFF))
        return bpf_redirect(60, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
