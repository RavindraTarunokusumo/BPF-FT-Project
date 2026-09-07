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
    
    // 1. Verify outer Ethernet header exists
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. Check for VLAN tag (802.1Q)
    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlan_hdr *vlh = (void *)(eth + 1);
    
    // 3. Verify VLAN header exists
    if ((void *)(vlh + 1) > data_end)
        return XDP_PASS;

    __be16 inner_proto = vlh->h_vlan_encapsulated_proto;
    
    // 4. Copy source and destination MAC addresses before adjust_head
    //    adjust_head invalidates all packet pointers (ctx->data, ctx->data_end, eth, etc.)
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    memcpy(src_mac, eth->h_source, ETH_ALEN);
    memcpy(dst_mac, eth->h_dest, ETH_ALEN);

    // 5. Pop the 4-byte VLAN tag
    bpf_xdp_adjust_head(ctx, 4);

    // 6. Reload data and data_end from ctx after adjust_head
    //    This is required because the verifier invalidates registers pointing to the packet.
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    // 7. Re-construct the Ethernet header at the new data pointer
    struct ethhdr *new_eth = data;
    
    // 8. Verify bounds for the new header write
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    // 9. Write the new Ethernet header fields
    new_eth->h_proto = inner_proto;
    memcpy(new_eth->h_source, src_mac, ETH_ALEN);
    memcpy(new_eth->h_dest, dst_mac, ETH_ALEN);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
