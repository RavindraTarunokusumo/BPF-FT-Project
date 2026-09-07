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
int xdp_v2_dev_nrf_l2_01(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlan_hdr *vlan = (void *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    __be16 inner_proto = vlan->h_vlan_encapsulated_proto;
    if (inner_proto == bpf_htons(0x8100)) {
        struct vlan_hdr *vlan2 = (void *)(vlan + 1);
        if ((void *)(vlan2 + 1) > data_end)
            return XDP_PASS;
        if (vlan2->h_vlan_encapsulated_proto == bpf_htons(0x8864))
            return XDP_TX;
    } else if (inner_proto == bpf_htons(0x8864)) {
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
