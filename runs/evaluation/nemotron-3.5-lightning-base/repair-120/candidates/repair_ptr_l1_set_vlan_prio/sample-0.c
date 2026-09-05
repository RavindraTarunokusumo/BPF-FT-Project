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

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlh = (void *)(eth + 1);
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;
        /* Set 802.1p priority to 7 (highest) in the VLAN TCI,
         * preserving the VID (12 bits) and CFI (1 bit) in bits 0..11. */
        vlh->h_vlan_TCI = (__be16)((ntohs(vlh->h_vlan_TCI) & 0x1FFF) | (7 << 13));
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
