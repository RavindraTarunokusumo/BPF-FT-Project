#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* VXLAN header: 8 bytes total (Reserved: 2, VNI: 3, Reserved: 3) */
#define VXLAN_HDR_LEN 8

/* XDP program entry point */
SEC("xdp")
int xdp_vxlan_decap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate outer Ethernet header (14 bytes) */
    if (data + ETH_HLEN > data_end)
        return XDP_PASS;

    /* 2. Validate Ethernet type is IPv4 (0x0800) */
    if (data[12] != 0x08 || data[13] != 0x00)
        return XDP_PASS;

    /* 3. Adjust pointer to IPv4 header (skip 14 bytes Ethernet) */
    struct iphdr *ip = data + ETH_HLEN;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 4. Validate IPv4 IHL = 5 (20 bytes header) */
    if (ip->ihl != 5)
        return XDP_PASS;

    /* 5. Validate IPv4 protocol is UDP (17) */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 6. Adjust pointer to UDP header (skip IPv4 header) */
    void *udp_start = (void *)(ip + 1);
    if (udp_start + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct udphdr *udp = udp_start;
    /* 7. Validate UDP destination port is 4789 (0xBCD) */
    if (udp->dest != htons(4789))
        return XDP_PASS;

    /* 8. Adjust pointer past UDP header (8 bytes) to VXLAN payload start */
    void *vxlan_start = udp_start + sizeof(struct udphdr);
    if (vxlan_start + VXLAN_HDR_LEN > data_end)
        return XDP_PASS;

    /* 9. Validate VXLAN header (8 bytes) - basic structure check */
    /* VXLAN: 2 bytes Reserved, 3 bytes VNI flags, 3 bytes Reserved */
    /* We simply verify the pointer bounds; no specific VNI bit masking required */

    /* 10. Adjust pointer past VXLAN header to inner Ethernet */
    void *inner_eth = vxlan_start + VXLAN_HDR_LEN;
    if (inner_eth + ETH_HLEN > data_end)
        return XDP_PASS;

    /* 11. Strip 50 outer encapsulation bytes using bpf_xdp_adjust_head */
    /* Total outer bytes: Ethernet(14) + IPv4(20) + UDP(8) + VXLAN(8) = 50 */
    if (bpf_xdp_adjust_head(ctx, 50) != 0)
        return XDP_PASS;

    /* 12. After adjustment, data points to the raw inner Ethernet frame.
       The program has successfully decapsulated the VXLAN packet. */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
