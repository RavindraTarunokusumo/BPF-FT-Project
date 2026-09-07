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
int xdp_transform_syn_ptr_l2_005_qinq_to_single_vlan(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x88A8) && eth->h_proto != bpf_htons(0x8100))
        return XDP_PASS;

    struct vlan_hdr *vlan1 = (void *)(eth + 1);
    if ((void *)(vlan1 + 1) > data_end)
        return XDP_PASS;

    if (vlan1->h_vlan_encapsulated_proto != bpf_htons(0x8100))
        return XDP_PASS;

    struct vlan_hdr *vlan2 = (void *)(vlan1 + 1);
    if ((void *)(vlan2 + 1) > data_end)
        return XDP_PASS;

    if (vlan2->h_vlan_encapsulated_proto != bpf_htons(0x8100))
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, 4) != 0)
        return XDP_PASS;

    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_8021Q);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
