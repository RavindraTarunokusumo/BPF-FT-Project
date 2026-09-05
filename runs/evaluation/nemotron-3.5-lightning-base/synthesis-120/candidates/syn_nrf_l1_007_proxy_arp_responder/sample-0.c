#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/* 
 * Proxy ARP Responder XDP program.
 * Responds to ARP requests targeting 192.168.100.1 with a synthesized reply.
 */

SEC("xdp")
int xdp_proxy_arp_responder(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth;
    struct arphdr_eth_ipv4 *arp;

    /* 
     * Validate that we have enough data for an Ethernet header.
     * sizeof(struct ethhdr) = 14 bytes.
     */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 
     * Verify EtherType is ARP (0x0806).
     * The Ethernet header is 14 bytes: 6 dst + 6 src + 2 type.
     * We check eth->h_proto after the header.
     */
    if (eth->h_proto != htons(ETH_P_ARP))
        return XDP_PASS;

    /* 
     * Now validate that we have enough data for the ARP header.
     * struct arphdr_eth_ipv4 is defined in <linux/if_arp.h> and
     * totals 28 bytes: 2 hardware type + 2 protocol type + 1 hw size + 1
     * proto size + 2 op + 6 sha + 4 spa + 6 tha + 4 tip = 28.
     */
    if (data + sizeof(*eth) + sizeof(*arp) > data_end)
        return XDP_PASS;

    arp = data + sizeof(*eth);

    /* 
     * Verify opcode is ARPOP_REQUEST (1).
     * ar_op is a 2-byte field in network byte order.
     */
    if (arp->ar_op != htons(ARPOP_REQUEST))
        return XDP_PASS;

    /* 
     * Verify the target IP address is 192.168.100.1.
     * ar_tip is the target IP in network byte order.
     * We compare against in_addr structure or directly with the value.
     * 192.168.100.1 in network byte order is 0xC0A86401.
     */
    if (arp->ar_tip != htonl(0xC0A86401))
        return XDP_PASS;

    /* 
     * Synthesize ARP Reply.
     * We need to modify the ARP packet in-place and update Ethernet header.
     * 
     * ARP Reply structure (same layout as request, but):
     * - ar_op = ARPOP_REPLY (2)
     * - ar_sha = sender MAC (our MAC: 02:00:00:00:00:01)
     * - ar_spa = sender IP (target IP: 192.168.100.1)
     * - ar_tha = target MAC (original sender MAC)
     * - ar_tpa = target IP (original target IP: 192.168.100.1)
     * 
     * Ethernet header swap:
     * - dst = original src
     * - src = our MAC 02:00:00:00:00:01
     */

    /* 
     * Set ARP opcode to REPLY (2) in network byte order.
     */
    arp->ar_op = htons(ARPOP_REPLY);

    /* 
     * Set sender hardware address (ar_sha) to our MAC: 02:00:00:00:00:01.
     * ar_sha is 6 bytes starting at offset 0 within arp struct (after ar_hwtype,
     * ar_proto, ar_hln, ar_pln, ar_op).
     * We access it via a char pointer offset.
     */
    unsigned char *sha = (unsigned char *)(arp + 1); /* points to ar_sha */
    sha[0] = 0x02; sha[1] = 0x00; sha[2] = 0x00;
    sha[3] = 0x00; sha[4] = 0x00; sha[5] = 0x01;

    /* 
     * Set sender IP address (ar_spa) to target IP 192.168.100.1.
     * ar_spa is 4 bytes. It follows ar_sha.
     * The layout from arp start:
     * - ar_hwtype (2)
     * - ar_proto (2)
     * - ar_hln (1)
     * - ar_pln (1)
     * - ar_op (2)
     * - ar_sha (6) -> total 14 bytes from arp start
     * - ar_spa (4) -> total 18 bytes from arp start
     * We can access ar_spa via offset arithmetic.
     * Alternatively, use the struct field if accessible, but bpf helpers
     * often require byte access. We'll use a pointer to ar_spa.
     * 
     * Let's calculate offset: 
     * sizeof(ar_hwtype) + sizeof(ar_proto) + sizeof(ar_hln) + sizeof(ar_pln) + sizeof(ar_op) + sizeof(ar_sha)
     * = 2 + 2 + 1 + 1 + 2 + 6 = 14.
     * So ar_spa is at arp + 14.
     */
    unsigned int *spa = (unsigned int *)((char *)arp + 14);
    *spa = htonl(0xC0A86401); /* 192.168.100.1 */

    /* 
     * Set target hardware address (ar_tha) to original sender MAC (ar_sha).
     * ar_tha follows ar_spa.
     * Offset from arp start: 14 (up to ar_spa) + 4 (ar_spa) = 18.
     * ar_tha is 6 bytes.
     */
    unsigned char *tha = (unsigned char *)((char *)arp + 18);
    /* Copy original sender MAC (ar_sha) to ar_tha */
    /* ar_sha is at arp + 8 (after ar_op at 2+2+1+1+2=8) */
    unsigned char *orig_sha = (unsigned char *)(arp + 1); /* arp + 1 is technically ar after eth header, but ar_sha offset within arp is 8 */
    /* Let's be precise: arp points to arphdr_eth_ipv4.
     * ar_hwtype at offset 0.
     * ar_proto at offset 2.
     * ar_hln at offset 4.
     * ar_pln at offset 5.
     * ar_op at offset 6.
     * ar_sha at offset 8 (6 bytes).
     * ar_spa at offset 14 (4 bytes).
     * ar_tha at offset 18 (6 bytes).
     * ar_tpa at offset 24 (4 bytes).
     * Total 28 bytes. */
    
    /* Copy orig_sha from ar_sha location */
    orig_sha = (unsigned char *)((char *)arp + 8);
    tha[0] = orig_sha[0]; tha[1] = orig_sha[1]; tha[2] = orig_sha[2];
    tha[3] = orig_sha[3]; tha[4] = orig_sha[4]; tha[5] = orig_sha[5];

    /* 
     * Set target IP address (ar_tpa) to original target IP (192.168.100.1).
     * ar_tpa is at offset 24 from arp start.
     */
    unsigned int *tp = (unsigned int *)((char *)arp + 24);
    *tp = htonl(0xC0A86401); /* 192.168.100.1 */

    /* 
     * Now update Ethernet header.
     * We need to swap MAC addresses and set source to our MAC.
     * 
     * Original Ethernet frame:
     * [6 bytes dst] [6 bytes src] [2 bytes ethertype]
     * 
     * For ARP reply, we want:
     * - Ethernet dst = original Ethernet src
     * - Ethernet src = 02:00:00:00:00:01
     * - Ethernet type remains ETH_P_ARP (0x0806)
     *
