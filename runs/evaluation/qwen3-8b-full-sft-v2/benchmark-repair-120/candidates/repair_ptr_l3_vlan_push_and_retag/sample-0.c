#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

    vlh->h_vlan_TCI = bpf_htons(500);
    vlh->h_vlan_encapsulated_proto = eth_copy.h_proto;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
