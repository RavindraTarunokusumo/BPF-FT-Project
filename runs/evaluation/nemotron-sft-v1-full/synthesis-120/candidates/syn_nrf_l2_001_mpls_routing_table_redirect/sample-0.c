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

struct mpls_hdr {
    __be32 label_and_exp;
};

SEC("xdp")
int xdp_route_syn_nrf_l2_001_mpls_routing_table_redirect(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    struct mpls_hdr *mpls = (void *)(eth + 1);
    if ((void *)(mpls + 1) > data_end)
        return XDP_PASS;

    __u32 label = bpf_ntohl(mpls->label_and_exp) >> 12;

    __u32 key = label;
    if (label == 500)
        key = 20;
    else if (label == 600)
        key = 21;

    __u32 *egress_ifindex = bpf_map_lookup_elem(&mpls_route_map, &key);
    if (egress_ifindex) {
        unsigned char tmp_mac[ETH_ALEN];
        __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);
        return bpf_redirect(*egress_ifindex, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
