#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;

    if (bpf_xdp_adjust_head(ctx, -20))
        return XDP_DROP;

    eth = (void *)(long)eth - 20;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    eth->h_proto = bpf_htons(ETH_P_IP);
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    ip->protocol = IPPROTO_IPIP;
    ip->ttl = 64;
    ip->saddr = bpf_htons(192U << 24 | 168 << 16 | 100 << 8 | 50);
    ip->daddr = bpf_htons(192U << 24 | 168 << 16 | 100 << 8 | 60);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
