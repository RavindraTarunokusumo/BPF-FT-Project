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
int xdp_filter_syn_pfs_l2_004_qinq_double_vlan_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x88A8) && eth->h_proto != bpf_htons(0x8100))
        return XDP_PASS;

    struct vlan_hdr *outer_vlan = (void *)(eth + 1);
    if ((void *)(outer_vlan + 1) > data_end)
        return XDP_PASS;

    if (outer_vlan->h_vlan_encapsulated_proto != bpf_htons(0x8100))
        return XDP_PASS;

    __u16 outer_vid = bpf_ntohs(outer_vlan->h_vlan_TCI) & 0x0FFF;

    struct vlan_hdr *inner_vlan = (void *)(outer_vlan + 1);
    if ((void *)(inner_vlan + 1) > data_end)
        return XDP_PASS;

    __u16 inner_vid = bpf_ntohs(inner_vlan->h_vlan_TCI) & 0x0FFF;

    if (outer_vid == 100 && inner_vid == 200)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
