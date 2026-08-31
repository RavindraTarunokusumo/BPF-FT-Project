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

    struct ethhdr eth_copy = *eth;
    if (bpf_xdp_adjust_head(ctx, -4))
        return XDP_DROP;

    // Verifier error: missing (void *)(new_eth + 1) > data_end check
    data = (void *)(long)ctx->data;
    struct ethhdr *new_eth = data;
    *new_eth = eth_copy;
    new_eth->h_proto = bpf_htons(ETH_P_8021Q);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
