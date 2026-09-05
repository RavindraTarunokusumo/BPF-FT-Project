#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int xdp_vlan_tag(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Check if frame is untagged IPv4 */
    if (eth->h_proto != ETH_P_IP)
        return XDP_PASS;

    /* Expand head by 4 bytes for VLAN tag */
    int ret = bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr));
    if (ret)
        return XDP_PASS;

    /* Re-validate packet pointers after adjustment */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Rewrite Ethernet header with ETH_P_8021Q */
    eth->h_proto = htons(ETH_P_8021Q);

    /* Insert VLAN header */
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    /* vlan_id == 305, encapsulated ETH_P_IP */
    vlan->h_vlan_TCI = htons(305 << VLAN_VID_SHIFT | htons(ETH_P_IP));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
