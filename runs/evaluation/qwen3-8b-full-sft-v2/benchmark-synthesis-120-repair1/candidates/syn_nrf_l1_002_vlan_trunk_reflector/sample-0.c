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
int xdp_route_syn_nrf_l1_002_vlan_trunk_reflector(struct xdp_md *ctx) {
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

    __u16 vid = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
    if (vid == 100) {
        __be64 tmp = bpf_ntoh64((__be64)eth->h_dest);
        eth->h_dest = bpf_htons64((__u64)eth->h_source);
        eth->h_source = bpf_ntoh64(tmp);
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";