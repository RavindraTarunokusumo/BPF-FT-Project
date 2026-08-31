#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
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

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    __sync_synchronize();

    new_eth->h_proto = bpf_htons(ETH_P_IP);
    struct iphdr *ip = (void *)(new_eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;
    ip->protocol = IPPROTO_IPIP;
    ip->check = 0;
    ip->ttl = 200;
    // Copy original IP header
    __builtin_memcpy(ip, eth + 1, sizeof(struct iphdr));
    ip->check = ~(__builtin_checksum_fast(ip, sizeof(struct iphdr)));

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
