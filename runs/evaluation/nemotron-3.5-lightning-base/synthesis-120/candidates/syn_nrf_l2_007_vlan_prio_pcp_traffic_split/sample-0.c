#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/errno.h>

/* XDP program entry point */
SEC("xdp")
int xdp_vlan_prio_pcp_split(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct vlan_hdr *vlan;

    /* 1. Validate minimal Ethernet frame size */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Verify EtherType is 802.1Q (0x8100) */
    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    /* 3. Validate VLAN header fits within the frame */
    if (data + sizeof(*eth) + sizeof(*vlan) > data_end)
        return XDP_PASS;

    vlan = data + sizeof(*eth);

    /* 4. Extract 3-bit PCP from VLAN TCI field.
       bpf_ntohs converts from network byte order (big-endian).
       The PCP occupies the top 3 bits of the 16-bit TCI field. */
    u16 tci = bpf_ntohs(vlan->h_vlan_TCI);
    u8 pcp = (u8)(tci >> 13);

    /* 5. Redirect based on PCP value */
    if (pcp >= 5) {
        /* Voice/Video priority -> high-priority queue */
        return bpf_redirect(8, 0);
    } else {
        /* Standard priority -> standard queue */
        return bpf_redirect(9, 0);
    }
}

/* Required license declaration for GPL */
char LICENSE[] = "GPL";
