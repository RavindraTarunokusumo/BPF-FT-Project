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
int xdp_filter_syn_pfs_l2_009_ip_in_ip_nested_loopback_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (outer_ip->protocol != IPPROTO_IPIP)
        return XDP_PASS;

    __u32 outer_hlen = outer_ip->ihl * 4;
    if (outer_hlen < sizeof(*outer_ip) || outer_hlen > 60)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)outer_ip + outer_hlen;
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    if ((ntohl(inner_ip->daddr) & 0xFF000000) == 0x7F000000)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
