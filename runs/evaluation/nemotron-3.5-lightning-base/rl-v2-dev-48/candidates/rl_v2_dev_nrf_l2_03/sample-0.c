#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

/* XDP program entry point */
SEC("xdp")
int vlan_demux_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct eth_hdr *eth;
    struct vlan_hdr *vlan;

    /* Verify Ethernet header bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Check for 802.1Q VLAN tag (ETH_P_8021Q = 0x8100) */
    if (eth->h_proto != htons(ETH_P_8021Q))
        return XDP_PASS;

    /* Verify VLAN header bounds */
    if (data + sizeof(*eth) + sizeof(*vlan) > data_end)
        return XDP_PASS;

    vlan = data + sizeof(*eth);

    /* Check VLAN ID (12-bit field, bits 12-15 of the first vlan header word) */
    if (vlan->h_vlan_TCI & htons(VLAN_VID_MASK)) {
        /* Extract VLAN ID and compare to 30 */
        if (vlan_vid(vlan) == 30) {
            /* Transmit virtual network frame with VLAN tag 30 */
            return XDP_TX;
        }
    }

    /* Pass all other packets: non-802.1Q, different VLAN IDs, untagged */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
