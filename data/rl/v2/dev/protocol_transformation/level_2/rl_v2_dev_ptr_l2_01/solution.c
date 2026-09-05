#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_retag_1(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        __u16 tci = bpf_ntohs(vlan->h_vlan_TCI);
        __u16 vlan_id = tci & 0x0FFF;
        if (vlan_id == 100) {
            __u16 new_tci = (tci & 0xF000) | (200 & 0x0FFF);
            vlan->h_vlan_TCI = bpf_htons(new_tci);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
