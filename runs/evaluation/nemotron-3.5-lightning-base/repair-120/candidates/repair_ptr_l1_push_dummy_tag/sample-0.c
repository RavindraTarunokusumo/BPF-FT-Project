#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Save the original Ethernet header contents on the stack */
    struct ethhdr eth_copy = *eth;

    /* Expand the packet by 4 bytes to make room for the VLAN tag */
    if (bpf_xdp_adjust_head(ctx, -4))
        return XDP_DROP;

    /* Reload packet pointers after the head adjustment */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;

    /* Verify that the adjusted packet still contains the Ethernet header */
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    /* Restore the original Ethernet header */
    *new_eth = eth_copy;

    /* Insert the 802.1Q VLAN tag: 0x8100 followed by VID 100 */
    new_eth->h_vlan_TCI = bpf_htons(0x100);   /* VID = 100, CFI = 0, PRI = 0 */
    new_eth->h_vlan_encapsulated_proto = bpf_htons(ETH_P_8021Q);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
