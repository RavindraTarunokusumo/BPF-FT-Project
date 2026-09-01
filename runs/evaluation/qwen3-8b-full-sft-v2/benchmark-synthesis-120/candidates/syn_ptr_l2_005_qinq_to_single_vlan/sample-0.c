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

struct vlanhdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_transform_syn_ptr_l2_005_qinq_to_single_vlan(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlanhdr *vlan = (void *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    __u16 proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
    if (proto != 0x8100)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, 4))
        return XDP_PASS;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(new_eth, eth, sizeof(*eth));
    new_eth->h_proto = bpf_htons(ETH_P_8021Q);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
