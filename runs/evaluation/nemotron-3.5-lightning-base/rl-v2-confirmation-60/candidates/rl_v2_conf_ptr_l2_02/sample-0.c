#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int xdp_vlan_tag_prepend(struct xdp_md *ctx)
{
    void *data;
    void *data_end;

    /* Retrieve packet boundaries */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Pointer to Ethernet header */
    struct ethhdr *eth = data;

    /* Check if frame is untagged IPv4 (eth->h_proto == ETH_P_IP) */
    if (eth->h_proto != ETH_P_IP)
        return XDP_PASS;

    /* Expand head by 4 bytes using adjust_head.
     * Negative value moves data forward, creating room for VLAN tag. */
    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)))
        return XDP_PASS;

    /* Re-validate packet pointers after adjustment */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > data_end)
        return XDP_PASS;

    /* Rewrite Ethernet header with ETH_P_8021Q (0x8100) */
    eth->h_proto = htons(ETH_P_8021Q);

    /* Pointer to the newly prepended VLAN header */
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);

    /* Insert VLAN tag: vlan_id == 302, encapsulated ETH_P_IP */
    vlan->h_vlan_TCI = htons(302 << 4 | htons(ETH_P_IP) & 0x0FFF);
    /* Ensure the encapsulated protocol is ETH_P_IP */
    vlan->h_vlan_encapsulated_proto = htons(ETH_P_IP);

    /* Forward the packet unconditionally */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
