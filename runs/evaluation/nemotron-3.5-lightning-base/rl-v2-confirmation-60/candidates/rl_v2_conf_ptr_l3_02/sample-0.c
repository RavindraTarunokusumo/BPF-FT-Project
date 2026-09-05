#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* XDP entry point */
SEC("xdp")
int xdp_gre_decap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify outer IPv4 header bounds */
    struct iphdr *outer_ip = (struct iphdr *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    /* Check if the outer protocol is GRE (47) */
    if (outer_ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    /* Calculate total encapsulation length:
     * outer_ip->ihl is in 4-byte units, so ihl * 4 gives IPv4 header length
     * + 4 bytes for the GRE header */
    int outer_len = (outer_ip->ihl * 4) + 4;

    /* Ensure the encapsulated payload fits within the packet */
    if ((void *)(eth + 1 + outer_len) > data_end)
        return XDP_PASS;

    /* Back up the original Ethernet header for later restoration if needed.
     * In this simple decap we will shift and rewrite, but keeping the backup
     * matches the typical pattern for header manipulation. */
    struct eth_hdr saved_eth;
    bpf_memcpy(&saved_eth, eth, sizeof(saved_eth));

    /* Shift packet head forward by outer_len + 4 bytes.
     * Note: The +4 accounts for the GRE header already included in outer_len,
     * but we adjust by the full encapsulation length to expose the inner frame. */
    int ret = bpf_xdp_adjust_head(ctx, outer_len);
    if (ret)
        return XDP_PASS;

    /* Re-validate packet pointers after head adjustment */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify we still have at least an Ethernet header */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Restore Ethernet header with ETH_P_IP to indicate inner IP payload.
     * We overwrite the old outer Ethernet header with the saved one,
     * but set the protocol type to ETH_P_IP (0x0800) since the inner
     * frame is now an IPv4 packet. */
    eth->h_proto = htons(ETH_P_IP);

    /* The packet now points to the inner Ethernet frame.
     * The driver/stack will treat it as a standard IP packet. */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
