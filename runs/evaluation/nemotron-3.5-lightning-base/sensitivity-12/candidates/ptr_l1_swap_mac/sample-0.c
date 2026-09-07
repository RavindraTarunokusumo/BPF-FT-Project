#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

/* XDP program entry point */
SEC("xdp")
int xdp_swap_mac(struct xdp_md *ctx)
{
    /* Pointer to the Ethernet header (layer 2 start) */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Check minimum frame size: 14 bytes for Ethernet header */
    if (data + ETH_HLEN > data_end) {
        /* Runt frame (< 14 bytes) - pass unchanged */
        return XDP_PASS;
    }

    /* Ethernet header structure:
     *   bytes 0-5:   dst MAC (6 bytes)
     *   bytes 6-11:  src MAC (6 bytes)
     *   bytes 12-13: EtherType (2 bytes)
     */
    struct ethhdr *eth = data;

    /* Verify we have the full 14-byte header after the initial check */
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    /* Byte-wise swap of destination and source MAC addresses */
    /* eth->h_dest   - 6 bytes (destination MAC) */
    /* eth->h_source - 6 bytes (source MAC) */
    unsigned char tmp[6];

    /* Save destination MAC to temporary buffer */
    memcpy(tmp, eth->h_dest, 6);

    /* Copy source MAC to destination */
    memcpy(eth->h_dest, eth->h_source, 6);

    /* Copy saved destination MAC to source */
    memcpy(eth->h_source, tmp, 6);

    /* All bytes after the 12-byte MAC area (EtherType, payload, FCS) are
     * automatically preserved by the kernel XDP infrastructure - we only
     * modified the first 12 bytes of the frame.
     */

    /* Pass the modified frame up the network stack */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
