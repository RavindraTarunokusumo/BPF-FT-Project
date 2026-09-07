#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* XDP program entry point */
SEC("xdp")
int xdp_gre_unwrap(struct xdp_md *ctx)
{
    void *data, *data_end;
    struct eth_hdr *eth;
    struct iphdr *outer_ip;
    u32 outer_len;
    void *eth_orig;

    /* Obtain packet boundaries */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header fits */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Verify outer IPv4 header fits */
    if (data + sizeof(*eth) + sizeof(*outer_ip) > data_end)
        return XDP_PASS;

    outer_ip = (struct iphdr *)(eth + 1);

    /* Check protocol == IPPROTO_GRE (47) */
    if (outer_ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    /* Calculate total encapsulation length:
     * outer_ip->ihl is in 4-byte units, so ihl * 4 gives outer IP header length.
     * + 4 bytes for the GRE header (protocol + checksum + key) */
    outer_len = (outer_ip->ihl * 4) + 4;

    /* Verify that the encapsulated payload exists within the original frame.
     * We need at least outer_len bytes after the Ethernet header. */
    if (data + sizeof(*eth) + outer_len > data_end)
        return XDP_PASS;

    /* Back up the original Ethernet header pointer */
    eth_orig = data;

    /* Shift packet head forward by outer_len bytes using bpf_xdp_adjust_head.
     * This advances the data pointer past the outer IP header and GRE header,
     * effectively unwrapping the GRE tunnel. */
    if (bpf_xdp_adjust_head(ctx, outer_len))
        return XDP_PASS;

    /* Re-validate packet pointers after adjustment.
     * data now points to the original Ethernet header location,
     * but the memory content has been shifted. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify that the Ethernet header and the new payload fit */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Update Ethernet header pointer to the new location */
    eth = data;

    /* Restore Ethernet type to ETH_P_IP (0x0800) since we removed the outer
     * IP header. The payload now starts with the inner protocol. */
    eth->h_proto = htons(ETH_P_IP);

    /* Unconditionally pass the packet */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
