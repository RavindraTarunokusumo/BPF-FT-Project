#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

/* XDP program entry point */
SEC("xdp")
int xdp_vlan_demux(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Check for 802.1Q VLAN tag (0x8100) */
    if (eth->h_proto != htons(ETH_P_8021Q))
        return XDP_PASS;

    /* Verify VLAN tag header bounds */
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    if ((void *)vlan + sizeof(*vlan) > data_end)
        return XDP_PASS;

    /* Check for VLAN ID 40 (0x28) */
    /* vlan_tci layout: priority(3) + CFI(1) + VLAN ID(12) */
    /* We use the constant from <linux/if_vlan.h> for portability */
    if (vlan->h_vlan_TCI & htons(IF_VLAN_ID_MASK) == htons(40)) {
        /* Direct isolated segment frame marked with VLAN 40 */
        return XDP_TX;
    }

    /* Pass all other packets: other VLAN IDs, untagged, non-IP traffic */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
