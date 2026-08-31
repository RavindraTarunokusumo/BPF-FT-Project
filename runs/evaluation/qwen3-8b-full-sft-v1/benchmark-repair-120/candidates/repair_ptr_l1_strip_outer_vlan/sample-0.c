#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlan_hdr *vlh = (void *)(eth + 1);
    if ((void *)(vlh + 1) > data_end)
        return XDP_PASS;

    __be16 inner_proto = vlh->h_vlan_encapsulated_proto;
    struct ethhdr eth_copy = *eth;

    __u64 adj = 4;
    if (data_end - adj < (void *)&eth_copy)
        return XDP_PASS;

    bpf_xdp_adjust_head(ctx, adj);

    struct ethhdr *new_eth = data;
    new_eth->h_proto = inner_proto;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
