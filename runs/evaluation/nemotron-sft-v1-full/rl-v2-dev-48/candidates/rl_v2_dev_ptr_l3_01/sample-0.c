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
int xdp_transform_rl_v2_dev_ptr_l3_01(struct xdp_md *ctx) {
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

    if (ip->protocol != 41)
        return XDP_PASS;

    __u32 outer_len = ip->ihl * 4;
    if (outer_len < sizeof(struct iphdr))
        return XDP_PASS;

    struct ethhdr backup_eth;
    __builtin_memcpy(&backup_eth, eth, sizeof(backup_eth));

    eth->h_proto = bpf_htons(ETH_P_IPV6);

    int ret = bpf_xdp_adjust_head(ctx, outer_len);
    if (ret)
        return XDP_PASS;

    struct ethhdr *new_eth = (void *)(long)ctx->data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(new_eth, &backup_eth, sizeof(backup_eth));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
