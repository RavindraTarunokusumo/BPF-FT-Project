#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

/* XDP program that inspects IPv6 packets and remarks the Traffic Class field
 * to Expedited Forwarding (0xB8 / 184). Preserves version and flow label.
 * Returns XDP_PASS for all packets. */

SEC("xdp")
int xdp_remark_tc(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Validate Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv6 packets (EtherType 0x86DD) */
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    /* Validate IPv6 header bounds */
    struct ipv6hdr *ip6 = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
        return XDP_PASS;

    /* Rewrite Traffic Class (DSCP/ECN) bits 20-27 to Expedited Forwarding 0xB8.
     * The Traffic Class field is 8 bits located at bits 20-27 of the
     * ipv6hdr->priority field (big-endian bit positions). We simply assign
     * the 8-bit value 0xB8 to the entire field. */
    ip6->priority = 0xB8;

    /* Preserve version and flow label – no modification required. */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
