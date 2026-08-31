#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct vlanhdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_qinq_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check for 802.1ad (0x88A8) or stacked 802.1Q (0x8100) outer tag
    if (eth->h_proto != bpf_htons(0x88A8) && eth->h_proto != bpf_htons(0x8100))
        return XDP_PASS;

    struct vlanhdr *outer_vlan = (void *)(eth + 1);
    if ((void *)(outer_vlan + 1) > data_end)
        return XDP_PASS;

    __u16 outer_vid = bpf_ntohs(outer_vlan->h_vlan_TCI) & 0x0FFF;

    // Inner tag must be 0x8100
    if (outer_vlan->h_vlan_encapsulated_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlanhdr *inner_vlan = (void *)(outer_vlan + 1);
    if ((void *)(inner_vlan + 1) > data_end)
        return XDP_PASS;

    __u16 inner_vid = bpf_ntohs(inner_vlan->h_vlan_TCI) & 0x0FFF;

    if (outer_vid == 100 && inner_vid == 200)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
