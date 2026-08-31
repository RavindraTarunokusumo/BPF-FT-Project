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

    if (eth->h_proto == bpf_htons(0x88A8)) {
        struct vlan_hdr *vlh_out = (void *)(eth + 1);
        if ((void *)(vlh_out + 1) > data_end)
            return XDP_PASS;

        if (vlh_out->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021Q)) {
            struct vlan_hdr *vlh_in = (void *)(vlh_out + 1);
            if ((void *)(vlh_in + 1) > data_end)
                return XDP_PASS;

            // Corrected: outer VID to 300, inner VID to 400
            __u16 tci_out = bpf_ntohs(vlh_out->h_vlan_TCI);
            vlh_out->h_vlan_TCI = bpf_htons((tci_out & 0xF000) | 300);

            __u16 tci_in = bpf_ntohs(vlh_in->h_vlan_TCI);
            vlh_in->h_vlan_TCI = bpf_htons((tci_in & 0xF000) | 400);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
