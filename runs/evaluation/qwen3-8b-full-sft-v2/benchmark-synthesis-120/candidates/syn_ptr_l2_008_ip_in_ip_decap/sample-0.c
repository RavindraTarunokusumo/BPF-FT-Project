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
int xdp_transform_syn_ptr_l2_008_ip_in_ip_decap(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_IPIP)
        return XDP_PASS;

    if (ip->ihl < 5)
        return XDP_PASS;

    int new_head = (void *)ip - data;
    if (new_head < 0 || (void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, 20))
        return XDP_DROP;

    eth = data;
    eth->h_proto = bpf_htons(ETH_P_IP);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
