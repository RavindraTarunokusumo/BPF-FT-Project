#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int xdp_push_vlan(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct vlan_hdr *vlan;

    /* 1. Verify Ethernet header bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Check if frame is untagged IPv4 (eth->h_proto == ETH_P_IP) */
    if (eth->h_proto != ETH_P_IP)
        return XDP_PASS;

    /* 3. Expand head by 4 bytes using bpf_xdp_adjust_head */
    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)) < 0)
        return XDP_PASS;

    /* 4. Re-validate packet pointers after head adjustment */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;
    /* After adjust_head, the Ethernet header is shifted down by 4 bytes.
     * The original eth->h_proto is now at eth + 12 (offset of h_proto in struct eth_hdr).
     * We need to rewrite the entire Ethernet header to preserve the original
     * source/destination addresses and push the protocol field down. */

    /* 5. Rewrite Ethernet header with ETH_P_8021Q (0x8100) */
    /* Build a minimal Ethernet header: keep original DA/SA, set protocol to 0x8100 */
    /* We construct a new eth_hdr inline to avoid undefined behavior with
       overlapping struct fields and to ensure the vlan tag occupies the
       exact 4-byte gap between the original protocol field and the payload. */

    /* Preserve original DA and SA (12 bytes total) */
    __u8 *dst = eth->h_dest;
    __u8 *src = eth->h_source;

    /* Shift the original protocol field (ETH_P_IP) down by 4 bytes
       to make room for the VLAN tag. The original eth_hdr layout is:
       - h_dest[6]
       - h_source[6]
       - h_proto[2]
       The vlan_hdr will be placed exactly where h_proto was, i.e. at
       eth + 12. To achieve this, we memmove the payload up by 4 bytes
       and write the VLAN tag at eth + 12. */

    /* Move payload up by sizeof(struct vlan_hdr) = 4 bytes */
    if (data + sizeof(*eth) + sizeof(struct vlan_hdr) > data_end)
        return XDP_PASS;

    /* memmove the IP payload up to make room for the VLAN header */
    memmove(data + 12 + sizeof(struct vlan_hdr), /* dest: after new eth_hdr + vlan */
            data + 12,                          /* src: original h_proto position */
            data_end - (data + 12));

    /* Now write the Ethernet header with ETH_P_8021Q at offset 12 */
    /* Destination MAC */
    eth->h_dest[0] = dst[0];
    eth->h_dest[1] = dst[1];
    eth->h_dest[2] = dst[2];
    eth->h_dest[3] = dst[3];
    eth->h_dest[4] = dst[4];
    eth->h_dest[5] = dst[5];

    /* Source MAC */
    eth->h_source[0] = src[0];
    eth->h_source[1] = src[1];
    eth->h_source[2] = src[2];
    eth->h_source[3] = src[3];
    eth->h_source[4] = src[4];
    eth->h_source[5] = src[5];

    /* Protocol: ETH_P_8021Q = 0x8100 */
    eth->h_proto = htons(ETH_P_8021Q);

    /* 6. Insert struct vlan_hdr with vlan_id == 304 and encapsulated ETH_P_IP */
    vlan = (struct vlan_hdr *)(eth + 1); /* vlan_hdr starts right after eth_hdr */

    /* vlan_hdr layout (gcc packed, no padding between fields):
       - vlan_tci __be16 (bits: CFI/DEI, VLAN_ID)
       - vlan_encapsulated_proto __be16
     */
    /* VLAN Tag Control Information:
       - bits 15:13: CFI (always 0)
       - bits 12:0:  VLAN_ID (12 bits)
       We set vlan_id = 304 => 0x0130
       vlan_tci = htons(0x1300) | (304 << 0) ... actually
       standard: vlan_tci = htons(vlan_id << 4 | CFI << 13 | DEI << 14)
       With CFI=0, DEI=0: vlan_tci = htons(304 << 4) = htons(0x1300)
       But to be safe and explicit we set the fields directly if struct allows,
       however struct vlan_hdr is typically:
       struct vlan_hdr {
           __be16 vlan_tci;
           __be16 vlan_encapsulated_proto;
       };
       So we set:
       vlan->vlan_tci = htons(304 << 4); /* VLAN_ID in upper 12 bits */
       vlan->vlan_encapsulated_proto = htons(ETH_P_IP);
     */
    vlan->vlan_tci = htons(304 << 4); /* VLAN_ID = 304, CFI=0, DEI=0 */
    vlan->vlan_encapsulated_proto = htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
