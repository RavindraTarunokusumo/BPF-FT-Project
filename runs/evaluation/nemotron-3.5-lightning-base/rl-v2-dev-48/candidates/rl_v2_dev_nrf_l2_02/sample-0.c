#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

/* XDP program entry point */
SEC("xdp")
int vlan_demux(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;

    /* Verify Ethernet header bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Check for 802.1Q VLAN tag (0x8100) */
    if (eth->h_proto == htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan;

        /* Verify VLAN header bounds */
        if (data + sizeof(*eth) + sizeof(*vlan) > data_end)
            return XDP_PASS;

        vlan = (struct vlan_hdr *)(eth + 1);

        /* Check if VLAN ID is 20 (0x14) */
        if (vlan->h_vlan_TCI & htons(0x0FFF) == htons(0x0014)) {
            /* Forward frame via XDP_TX */
            return XDP_TX;
        }
    }

    /* Pass all other packets: non-VLAN, other VLAN IDs, untagged */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
