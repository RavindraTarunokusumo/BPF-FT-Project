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
int xdp_push_vlan_3(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct ethhdr eth_copy;
        __builtin_memcpy(&eth_copy, eth, sizeof(struct ethhdr));

        if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)))
            return XDP_DROP;

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        struct ethhdr *new_eth = data;
        if ((void *)(new_eth + 1) > data_end)
            return XDP_DROP;

        struct vlan_hdr *vlan = (void *)(new_eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_DROP;

        __builtin_memcpy(new_eth, &eth_copy, sizeof(struct ethhdr));
        new_eth->h_proto = bpf_htons(ETH_P_8021Q);

        vlan->h_vlan_TCI = bpf_htons(303);
        vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
