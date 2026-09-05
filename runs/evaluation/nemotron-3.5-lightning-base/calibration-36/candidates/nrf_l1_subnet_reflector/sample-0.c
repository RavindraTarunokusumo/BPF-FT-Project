/* XDP program: nrf_l1_subnet_reflector
 *
 * Reflects packets whose IPv4 destination address belongs to the test
 * subnet 192.0.2.0/24 (0xC0000200/24) by swapping the Ethernet source
 * and destination addresses and returning XDP_TX. All other packets
 * (non-matching destinations, malformed frames, non-IPv4) are passed
 * unchanged with XDP_PASS.
 *
 * Compilation:  clang -target bpf -O2 -c nrf_l1_subnet_reflector.c -o nrf_l1_subnet_reflector.o
 * Verification:  The program is verifier-safe: it checks bounds for the
 *                Ethernet and IPv4 headers, validates the protocol type,
 *                and uses only safe arithmetic.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* XDP entry point */
SEC("xdp")
int nrf_l1_subnet_reflector(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify we have at least an Ethernet header */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* Check EtherType == IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify we have at least an IPv4 header after the Ethernet header */
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);

    /* Check that the IPv4 destination address belongs to 192.0.2.0/24
     * 192.0.2.0   = 0xC0000200
     * /24 mask    = 0xFFFFFF00
     * Condition: (ntohl(ip->daddr) & 0xFFFFFF00) == 0xC0000200
     */
    if ((bpf_ntohl(ip->daddr) & 0xFFFFFF00) != 0xC0000200)
        return XDP_PASS;

    /* Destination is in the reflected subnet -> swap Ethernet MACs */
    /* Swap destination */
    unsigned char tmp = eth->h_dest[0];
    eth->h_dest[0] = eth->h_source[0];
    eth->h_source[0] = tmp;

    tmp = eth->h_dest[1];
    eth->h_dest[1] = eth->h_source[1];
    eth->h_source[1] = tmp;

    tmp = eth->h_dest[2];
    eth->h_dest[2] = eth->h_source[2];
    eth->h_source[2] = tmp;

    tmp = eth->h_dest[3];
    eth->h_dest[3] = eth->h_source[3];
    eth->h_source[3] = tmp;

    tmp = eth->h_dest[4];
    eth->h_dest[4] = eth->h_source[4];
    eth->h_source[4] = tmp;

    tmp = eth->h_dest[5];
    eth->h_dest[5] = eth->h_source[5];
    eth->h_source[5] = tmp;

    /* Transmit the modified frame */
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
