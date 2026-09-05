/* XDP program: IPv6 ND Spoof Guard
 * Protects against rogue IPv6 Router Advertisement attacks via
 * unsolicited Neighbor Advertisements (Type 136) claiming router status.
 *
 * Drops packets where:
 *   - ICMPv6 Type == 136 (Neighbor Advertisement)
 *   - R-bit (bit 31) == 1  AND  S-bit (bit 30) == 0
 *
 * Passes all other traffic.
 *
 * Compilation: clang -target bpf -O2 -c xdp_nd_spoof_guard.c -o xdp_nd_spoof_guard.o
 * License: GPL
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/ctx/sk_buff.h>

/* ICMPv6 Neighbor Advertisement header (24 bytes)
 * Defined by RFC 4861.  Layout matches the kernel struct
 * icmp6_na_hdr for verifier compatibility.
 */
struct icmp6_na_hdr {
    struct icmp6_hdr    icmp6_hdr;   /* 8 bytes: type + code + checksum + reserved */
    __u8                na_target[16]; /* Target address */
};

/* XDP program entry point */
SEC("xdp")
int xdp_nd_spoof_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Parse Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate EtherType == IPv6 (0x86DD) */
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    /* 3. Parse IPv6 header */
    struct ipv6_hdr *ip6 = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
        return XDP_PASS;

    /* 4. Verify next header is ICMPv6 */
    if (ip6->nexthdr != IPPROTO_ICMPV6)
        return XDP_PASS;

    /* 5. Parse ICMPv6 header */
    struct icmp6_hdr *icmp6 = data + sizeof(*eth) + sizeof(*ip6);
    if (data + sizeof(*eth) + sizeof(*ip6) + sizeof(*icmp6) > data_end)
        return XDP_PASS;

    /* 6. Verify ICMPv6 type == 136 (Neighbor Advertisement) */
    if (icmp6->icmp6_type != ICMPV6_NA)
        return XDP_PASS;

    /* 7. Validate ICMPv6 NA payload bounds (24 bytes for target address)
     *    Total ICMPv6 NA = 8 (base) + 16 (target) = 24 bytes.
     *    We already checked the base header; now ensure the full payload fits.
     */
    if (data + sizeof(*eth) + sizeof(*ip6) + sizeof(*icmp6) + 16 > data_end)
        return XDP_PASS;

    /* 8. Cast to ICMPv6 NA structure and extract flags */
    struct icmp6_na_hdr *na = (struct icmp6_na_hdr *)icmp6;

    /* Flags are stored in the 4-byte 'reserved' field of icmp6_hdr.
     * Bit 31 (0x80000000) = Router flag (R)
     * Bit 30 (0x40000000) = Solicited flag (S)
     */
    __u32 flags = na->icmp6_hdr.icmp6_reserved;

    /* 9. Drop if unsolicited router advertisement claim:
     *    R == 1  AND  S == 0
     */
    if ((flags & 0x80000000) && !(flags & 0x40000000))
        return XDP_DROP;

    /* All other cases pass */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
