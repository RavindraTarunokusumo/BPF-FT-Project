#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Single unambiguous definition of the VLAN tag header.
 * Matches the layout expected by bpf_xdp_adjust_head and the
 * 802.1ad tag format: TCI (2 bytes) followed by encapsulated protocol (2 bytes). */
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

    struct ethhdr eth_copy = *eth;
    /* Pull the Ethernet header forward by 4 bytes to make room for the VLAN tag. */
    if (bpf_xdp_adjust_head(ctx, -4))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    *new_eth = eth_copy;
    new_eth->h_proto = bpf_htons(0x88A8);

    struct vlan_hdr *vlh = (void *)(new_eth + 1);
    if ((void *)(vlh + 1) > data_end)
        return XDP_DROP;

    /* VID 500 -> TCI = 0x0219 (VID << 4 | PRIO) */
    vlh->h_vlan_TCI = bpf_htons(500 << 4);
    vlh->h_vlan_encapsulated_proto = eth_copy.h_proto;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
