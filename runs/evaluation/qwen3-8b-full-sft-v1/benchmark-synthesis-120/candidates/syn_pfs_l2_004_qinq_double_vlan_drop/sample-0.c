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


SEC("xdp")
int xdp_filter_syn_pfs_l2_004_qinq_double_vlan_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_QINQ))
        return XDP_PASS;

    struct vlanhdr *vlan = (void *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    __u16 outer_vlan = vlan->h_vlan_TCI & 0x0FFF;
    if (outer_vlan != 100)
        return XDP_PASS;

    if (vlan->h_proto != bpf_htons(ETH_P_VLAN))
        return XDP_PASS;

    struct vlanhdr *inner_vlan = (void *)(vlan + 1);
    if ((void *)(inner_vlan + 1) > data_end)
        return XDP_PASS;

    __u16 inner_vlan_id = inner_vlan->h_vlan_TCI & 0x0FFF;
    if (inner_vlan_id == 200)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
