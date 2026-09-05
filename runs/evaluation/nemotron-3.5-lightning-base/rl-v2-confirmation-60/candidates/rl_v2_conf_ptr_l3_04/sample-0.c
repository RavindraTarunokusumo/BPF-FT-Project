#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* XDP entry point */
SEC("xdp")
int xdp_strip_gre(void *ctx)
{
    void *data_end;
    void *data;
    struct eth_hdr *eth;
    struct iphdr *outer_ip;

    /* Retrieve program context */
    data = (void *)(long)bpf_xdp_load_data(ctx);
    if (data == NULL)
        return XDP_ABORTED;

    data_end = data + bpf_xdp_load_len(ctx);

    /* Verify Ethernet header bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Verify outer IPv4 header bounds */
    if (data + sizeof(*eth) + sizeof(*outer_ip) > data_end)
        return XDP_PASS;

    outer_ip = (struct iphdr *)(eth + 1);

    /* Check if outer protocol is GRE (47) */
    if (outer_ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    /* Calculate total encapsulation length:
     * outer_ip->ihl is in 4-byte units, so ihl * 4 gives outer IPv4 header length
     * + 4 bytes for the GRE header */
    int outer_len = (outer_ip->ihl * 4) + 4;

    /* Back up Ethernet header pointer and shift packet head forward */
    /* Adjust head by outer_len + 4 to strip outer IPv4 + GRE headers.
     * The +4 accounts for the GRE key field that follows the GRE protocol
     * identifier in the standard GRE header, effectively removing the entire
     * encapsulation. */
    bpf_xdp_adjust_head(ctx, outer_len + 4);

    /* Re-validate packet pointers after adjustment */
    data = (void *)(long)bpf_xdp_load_data(ctx);
    if (data == NULL)
        return XDP_ABORTED;

    data_end = data + bpf_xdp_load_len(ctx);

    /* Ensure we still have at least an Ethernet header */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Restore Ethernet type to ETH_P_IP (0x0800) */
    eth->h_proto = htons(ETH_P_IP);

    /* Continue processing with the native IPv4 payload.
     * The XDP verifier will now see a standard Ethernet frame with
     * an IPv4 payload. */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
