/* XDP program: SRv6 to GTP-U translation router
 * Matches SRv6 packets with active Segment ID 2001:db8:ffff::/48
 * and redirects to 5G UPF gateway (ifindex 60).
 * All other traffic is passed.
 *
 * Compilation: clang -target bpf -O2 -c xdp_srv6_gtpu_redirect.c -o xdp_srv6_gtpu_redirect.o
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

/* SRv6 Routing Header definition (struct srv6_hdr)
 * Defined in linux/sr.h or linux/in6.h depending on kernel version.
 * We define it here for self-contained compilation.
 */
struct srv6_hdr {
    __be32 routing_type;   /* 4 for SRv6 routing */
    __be32 segments_left;  /* Number of remaining segments */
    /* Followed by segment list (128-bit IPv6 addresses) */
};

/* Prefix 2001:db8:ffff::/48 in network byte order (big-endian)
 * 2001:0db8:ffff:: -> first 6 groups (48 bits) = 2001:0db8:ffff
 * In wire format (network byte order) as 4 __be32 values:
 * 2001 -> 0x2001
 * 0db8 -> 0x0db8
 * ffff -> 0xffff
 * next 3 groups (96 bits) are zero -> 0x0000, 0x0000, 0x0000
 */
static const __be32 prefix_sid[4] = {
    cpu_to_be32(0x20010db8),
    cpu_to_be32(0xffff0000),
    cpu_to_be32(0x00000000),
    cpu_to_be32(0x00000000)
};

/* XDP entry point */
SEC("xdp")
int xdp_srv6_gtpu_redirect(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet frame minimum size */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate IPv6 packet */
    /* Check IPv6 header starts after Ethernet header */
    struct ipv6hdr *ip6 = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
        return XDP_PASS;

    /* 3. Verify next header == 43 (SRH) */
    if (ip6->nexthdr != IPPROTO_ROUTING)
        return XDP_PASS;

    /* 4. Validate SRH bounds and verify routing_type == 4 */
    /* SRH starts immediately after IPv6 header */
    struct srv6_hdr *srh = (struct srv6_hdr *)(ip6 + 1);
    if ((void *)srh + sizeof(*srh) > data_end)
        return XDP_PASS;

    /* Verify routing_type == 4 (SRv6) */
    if (srh->routing_type != 4)
        return XDP_PASS;

    /* 5. Check segments_left > 0 to have an active segment */
    if (srh->segments_left == 0)
        return XDP_PASS;

    /* 6. Get the active Segment ID (first segment in the segment list)
     *    SRH segment list starts right after the fixed header fields.
     *    Fixed part: routing_type (4 bytes) + segments_left (4 bytes) = 8 bytes
     *    First segment is a 128-bit (16-byte) IPv6 address.
     */
    struct srv6_seg *active_sid = (struct srv6_seg *)((void *)srh + sizeof(*srh));

    /* Verify active SID fits within packet bounds */
    if ((void *)active_sid + sizeof(*active_sid) > data_end)
        return XDP_PASS;

    /* 7. Compare active SID against prefix 2001:db8:ffff::/48
     *    We compare the first 64 bits (first two __be32 values) of the SID
     *    against the prefix. The prefix 2001:db8:ffff::/48 means
     *    first 48 bits must match 2001:0db8:ffff.
     *    In __be32 terms (big-endian):
     *    - First __be32: 0x20010db8 (covers first 32 bits)
     *    - Second __be32: must have upper 16 bits == 0xffff, lower 16 bits don't matter for /48
     *    We perform a masked comparison.
     */
    const __be32 *sid_as_be32 = (const __be32 *)active_sid;
    /* Mask for /48: first 48 bits must match, last 16 bits of second word don't care */
    const __be32 mask = cpu_to_be32(0xffff0000);

    if ((sid_as_be32[0] == prefix_sid[0]) &&
        (sid_as_be32[1] & mask) == (prefix_sid[1] & mask)) {
        /* Matching SRv6 active SID: redirect to 5G UPF gateway ifindex 60 */
        return bpf_redirect(60, 0);
    }

    /* 8. Non-matching SRv6 packets or other traffic: pass */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
