/* XDP VXLAN Encapsulation Program
 * Task: syn_ptr_l3_001_vxlan_encap_push
 * Category: protocol_transformation
 * Difficulty: level_3
 *
 * Encapsulates incoming raw IPv4 frames into VXLAN (UDP port 4789, VNI 100).
 * Uses bpf_xdp_adjust_head to expand headroom by 50 bytes.
 * Computes outer IPv4 checksum.
 * Returns XDP_PASS.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* VXLAN header definition (8 bytes)
 * Bit 31: Reserved (must be 0)
 * Bits 30-24: VN (Version) = 0x7
 * Bits 23-16: Reserved (must be 0)
 * Bits 15-8:  Reserved (must be 0)
 * Bits 7-0:   VNI (20 bits, lower 12 bits + 8 reserved)
 * Note: Standard VXLAN header is 8 bytes.
 */
struct vxlan_hdr {
    __be32 flags_reserved_vni;
};

/* Ethernet header */
struct eth_hdr {
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    __be16 h_proto;
};

/* IPv4 header minimum size (20 bytes) */
#define IP_HDR_MIN_SIZE 20

/* UDP header minimum size (8 bytes) */
#define UDP_HDR_MIN_SIZE 8

/* Maximum number of adjustments allowed for headroom */
#define MAX_HEADROOM_ADJ 50

/* XDP program entry point */
SEC("xdp")
int xdp_vxlan_encap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct vxlan_hdr *vxlan;
    int eth_type;
    int iphdr_len;
    int udp_hdr_len;
    int total_extra;

    /* 1. Validate that we have at least an Ethernet header */
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    eth = data;

    /* 2. Validate Ethernet type is IPv4 (0x0800) */
    eth_type = bpf_ntohs(eth->h_proto);
    if (eth_type != ETH_P_IP) {
        /* Not IPv4; we cannot process, but we still pass */
        return XDP_PASS;
    }

    /* 3. Validate IPv4 header bounds */
    if (data + sizeof(*eth) + IP_HDR_MIN_SIZE > data_end) {
        return XDP_PASS;
    }

    ip = (struct iphdr *)(eth + 1);

    /* Verify IPv4 header fits within the packet */
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    /* iphdr->ihl is in 32-bit words; convert to bytes */
    iphdr_len = ip->ihl * 4;
    if (iphdr_len < IP_HDR_MIN_SIZE) {
        iphdr_len = IP_HDR_MIN_SIZE;
    }

    /* Ensure the full IPv4 header is present */
    if ((void *)ip + iphdr_len > data_end) {
        return XDP_PASS;
    }

    /* 4. Expand packet headroom by 50 bytes using bpf_xdp_adjust_head */
    /* This moves the start of the packet data back by 50 bytes,
     * effectively adding 50 bytes of headroom at the beginning. */
    int adjust_ret = bpf_xdp_adjust_head(ctx, -50);
    if (adjust_ret) {
        /* Adjustment failed (e.g., not enough headroom in the driver) */
        bpf_printk("xdp_vxlan_encap: bpf_xdp_adjust_head failed (%d)\n", adjust_ret);
        return XDP_PASS;
    }

    /* Re-validate data pointers after adjustment.
     * adjust_head shifts data->data and data_end accordingly.
     * We must re-cast our pointers. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Re-validate Ethernet header after adjustment */
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    /* 5. Populate outer Ethernet header
     * We swap the source and destination MAC addresses.
     * The outer source MAC is set to a placeholder (bpf_xdp_adjust_head
     * typically preserves the original DMA address, but we explicitly
     * write a known value for this encapsulation task).
     * The outer destination MAC is the original inner source MAC. */
    struct eth_hdr *outer_eth = data;

    /* Save original inner MACs for later use (inner dst -> outer src) */
    unsigned char inner_dst[ETH_ALEN];
    unsigned char inner_src[ETH_ALEN];

    bpf_probe_read_kernel(inner_dst, ETH_ALEN, eth->h_dest);
    bpf_probe_read_kernel(inner_src, ETH_ALEN, eth->h_source);

    /* Set outer Ethernet header fields */
    /* Outer Dest MAC: original inner source MAC */
    bpf_probe_write_kernel(outer_eth->h_dest, inner_src, ETH_ALEN);
    /* Outer Src MAC: placeholder (e.g., 00:00:00:00:00:01) or original inner dst */
    /* For this task, we set outer src to a fixed value to demonstrate encapsulation */
    unsigned char outer_src_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    bpf_probe_write_kernel(outer_eth->h_source, outer_src_mac, ETH_ALEN);

    /* Outer EtherType: IPv4 (0x0800) */
    outer_eth->h_proto = bpf_htons(ETH_P_IP);

    /* 6. Populate outer IPv4 header
     * The outer IPv4 header follows the outer Ethernet header.
     * We construct it manually in the headroom space. */
    struct iphdr *outer_ip;

    /* Calculate offset for outer IP header.
     * Outer Eth (14 bytes) + Outer IP Header (minimum 20 bytes).
     * We need to ensure data has enough space.
     * After adjust_head(-50), data points to the start of the new headroom.
     * The original packet starts at data + 50.
     * We will write the outer headers starting at data + 14 (after eth).
     * But bpf_xdp_adjust_head moves the *entire* packet view.
     * Let's re-examine the pointer arithmetic.

     * After bpf_xdp_adjust_head(ctx, -50):
     * ctx->data points to the start of the 50-byte headroom added.
     * The original packet data starts at ctx->data + 50.
     * However, usually, we want to prepend headers.
     * The standard pattern for XDP encapsulation with adjust_head(-N)
     * is to write headers at the beginning of the mapped region (ctx->data),
     * and the original packet shifts up by N bytes.

     * Let's assume the program writes the outer Ethernet header at data[0].
     * Then the outer IP header starts at data + sizeof(struct eth_hdr).
     * The original inner Ethernet header (which was at data[0] originally)
     * is now at data[50] (due to -50 adjust).

     * Wait, bpf_xdp_adjust_head(ctx, -50) adjusts the *start* of the
     * packet buffer visible to the program. If the driver had 50 bytes
     * of headroom, this makes them usable. If not, it fails.
     * Assuming it succeeds, we can write our new headers at the very start
     * of `data` (which is `ctx->data`).

     * Let's write the outer Ethernet header at `data`.
     * The outer IP header will be at `data + sizeof(struct eth_hdr)`.
     * The original inner Ethernet header is now at `data + 50` (if adjust_head
     * shifted the view, but usually adjust_head just adjusts the `data` pointer
     * returned by the helper, the underlying buffer is fixed.
     * Actually, `bpf_xdp_adjust_head` adjusts `ctx->data`.
     * If I write headers at `ctx->data`, the original packet starts at `ctx->data + 50`.

     * Let's verify the layout:
     * [ Headroom (50 bytes
