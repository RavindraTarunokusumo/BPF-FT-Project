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
int xdp_decap_vlan_pop_tr09(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        __u16 vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
        if (vlan_id == 159) {
            __u16 inner_proto = vlan->h_vlan_encapsulated_proto;
            struct ethhdr eth_backup;
            __builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));
            eth_backup.h_proto = inner_proto;

            if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlan_hdr)))
                return XDP_DROP;

            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end)
                return XDP_DROP;

            __builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
