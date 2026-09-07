/* XDP program: Replace Ethernet destination MAC with 02:00:00:00:00:99
 *
 * Category   : protocol_transformation
 * Difficulty : level_1
 *
 * Replaces eth->h_dest with the fixed MAC address while preserving
 * source MAC, EtherType, payload, and packet length. Packets shorter
 * than 14 bytes are passed unchanged.
 *
 * License: GPL
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/ctx/sk_buff.h>

SEC("xdp")
int xdp_replace_dest_mac(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Ensure we have at least an Ethernet header (14 bytes) */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* Verify the Ethernet header fits within the packet */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Replace the destination MAC address with 02:00:00:00:00:99 */
    eth->h_dest[0] = 0x02;
    eth->h_dest[1] = 0x00;
    eth->h_dest[2] = 0x00;
    eth->h_dest[3] = 0x00;
    eth->h_dest[4] = 0x00;
    eth->h_dest[5] = 0x99;

    /* Source MAC, EtherType, payload, and packet length are preserved
     * automatically because we only modify the six destination bytes.
     */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
