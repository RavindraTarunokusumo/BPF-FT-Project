#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

/* XDP program entry point */
SEC("xdp")
int xdp_vlan_rewrite(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Check for 802.1Q VLAN tag (EtherType 0x8100) */
    if (eth->h_proto != htons(ETH_P_8021Q))
        return XDP_PASS;

    /* Verify VLAN header bounds after Ethernet header */
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    /* Check if VLAN ID is 100 (VID field in TCI, bits 12-0) */
    if (vlan->h_vlan_TCI & VLAN_VID_MASK) {
        /* Extract VID to compare; VLAN_VID_MASK is 0x0FFF */
        __be16 vid = vlan->h_vlan_TCI & cpu_to_be16(VLAN_VID_MASK);
        if (vid != cpu_to_be16(100))
            return XDP_PASS;
    } else {
        /* No VID set, skip */
        return XDP_PASS;
    }

    /* In-place TCI rewrite: preserve priority bits (bits 13-15),
     * set VID to 200 */
    __be16 new_tci;

    /* Extract priority bits (3 bits: CFI/DEI and priority) */
    __u16 prio = vlan->h_vlan_TCI & 0xE000; /* bits 13-15 */

    /* Set new VID 200 into lower 12 bits */
    new_tci = cpu_to_be16(prio | 200);

    /* Write back in-place */
    vlan->h_vlan_TCI = new_tci;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
