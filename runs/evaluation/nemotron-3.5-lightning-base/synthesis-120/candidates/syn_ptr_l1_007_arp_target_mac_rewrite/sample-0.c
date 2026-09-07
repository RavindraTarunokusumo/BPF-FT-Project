#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <bpf/ctx/sk_buff.h>

/* XDP program that inspects ARP Reply packets and rewrites the Target
 * Hardware Address (ar_tha) to a fixed value.
 *
 * The program validates that the packet contains sufficient data for
 * an Ethernet header and an ARP header (struct arphdr_eth_ipv4), then
 * checks if the ARP operation is a Reply (ar_op == 2). If so, it
 * overwrites the six-byte Target Hardware Address field with the
 * pattern 02:AA:BB:CC:DD:EE.
 *
 * Finally, the program returns XDP_PASS to allow normal packet processing.
 */

SEC("xdp")
int arp_target_mac_rewrite(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Ensure we have at least an Ethernet header. */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify EtherType is ARP (0x0806). */
    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    /* Ensure we have enough room for the ARP header (struct arphdr_eth_ipv4).
     * This structure is defined in <linux/if_arp.h> and contains:
     *   - ar_hrd: hardware type (2 bytes)
     *   - ar_pro: protocol type (2 bytes)
     *   - ar_hln: hardware address length (1 byte)
     *   - ar_pln: protocol address length (1 byte)
     *   - ar_op: operation code (2 bytes)
     *   - ar_sha: sender hardware address (6 bytes)
     *   - ar_sip: sender protocol address (4 bytes)
     *   - ar_tha: target hardware address (6 bytes)
     *   - ar_tip: target protocol address (4 bytes)
     * Total fixed size: 28 bytes.
     */
    if (data + sizeof(*eth) + sizeof(struct arphdr_eth_ipv4) > data_end)
        return XDP_PASS;

    struct arphdr_eth_ipv4 *arp = data + sizeof(*eth);

    /* Check that the ARP operation is a Reply (2). */
    if (arp->ar_op != bpf_htons(2))
        return XDP_PASS;

    /* Rewrite the Target Hardware Address (ar_tha) to 02:AA:BB:CC:DD:EE.
     * ar_tha is the first 6 bytes after ar_op in the ARP header.
     */
    arp->ar_tha[0] = 0x02;
    arp->ar_tha[1] = 0xAA;
    arp->ar_tha[2] = 0xBB;
    arp->ar_tha[3] = 0xCC;
    arp->ar_tha[4] = 0xDD;
    arp->ar_tha[5] = 0xEE;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
