#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/string.h>

/* SRv6 Routing Header (Type 4) definition.
 * The header immediately follows the IPv6 header.
 * The first 8 bytes are the header: Next Header, Header Length, Routing Type, Segments Left.
 * Header Length is in 8-byte units. Total header size = (hdr_len + 1) * 8 bytes.
 */
struct srh {
    __be32 hdr;   /* bits: Next Header(8) | Header Length(8) | Routing Type(8) | Segments Left(8) */
    __be32 segments[0]; /* Flexible array of 128-bit segments */
};

/* Map definition: per-CPU array with 4 slots.
 * Slot 0: Segments Left == 0
 * Slot 1: Segments Left == 1
 * Slot 2: Segments Left == 2
 * Slot 3: Segments Left >= 3 (capped)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} srv6_sl_map SEC(".maps");

SEC("xdp")
int xdp_srv6_sl_histogram(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv6 traffic (EtherType 0x86DD) */
    if (eth->h_proto != htons(ETH_P_IPV6))
        return XDP_PASS;

    /* Parse IPv6 header */
    struct ipv6hdr *ip6 = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
        return XDP_PASS;

    /* Verify Next Header == 43 (Routing Header) */
    if (ip6->nexthdr != IPPROTO_ROUTING)
        return XDP_PASS;

    /* Parse SRH header. It starts immediately after the IPv6 header.
     * The first 4 bytes contain: Next Header(1) | Header Length(1) | Routing Type(1) | Segments Left(1)
     * We use a 4-byte access to capture all fields at once.
     */
    if (data + sizeof(*eth) + sizeof(*ip6) + 4 > data_end)
        return XDP_PASS;

    struct srh *srh = (struct srh *)(ip6 + 1);
    /* Extract fields from the packed header word.
     * Layout (big-endian, network byte order):
     * Bits 31-24: Next Header
     * Bits 23-16: Header Length
     * Bits 15-8:  Routing Type
     * Bits 7-0:   Segments Left
     */
    __u8 nr = (srh->hdr >> 24) & 0xFF;       /* Next Header */
    __u8 hdr_len = (srh->hdr >> 16) & 0xFF;  /* Header Length */
    __u8 rt = (srh->hdr >> 8) & 0xFF;        /* Routing Type */
    __u8 sl = srh->hdr & 0xFF;               /* Segments Left */

    /* Verify Next Header == 43 and Routing Type == 4 */
    if (nr != 43 || rt != 4)
        return XDP_PASS;

    /* Verify that the SRH has enough space for at least the header.
     * Total SRH size = (hdr_len + 1) * 8 bytes.
     * We only need to ensure the header itself is present (4 bytes already checked).
     * Additional segment validation is not required for this histogram.
     */
    (void)hdr_len; /* Header length validated by presence check above */

    /* Classify Segments Left into slots 0..3 (cap at slot 3) */
    __u32 slot;
    if (sl <= 2) {
        slot = sl; /* slot 0, 1, or 2 */
    } else {
        slot = 3;  /* slot 3 for sl >= 3 */
    }

    /* Increment the per-CPU counter */
    __u32 key = slot;
    __u64 *val = bpf_map_lookup_elem(&srv6_sl_map, &key);
    if (val) {
        (*val)++;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
