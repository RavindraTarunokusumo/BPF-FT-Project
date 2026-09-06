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
int xdp_transform_rl_v2_conf_ptr_l3_04(struct xdp_md *ctx) {
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

    if (outer_ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    __u32 outer_len = outer_ip->ihl * 4;
    if (outer_len < sizeof(struct iphdr))
        return XDP_PASS;

    struct ethhdr saved_eth;
    __builtin_memcpy(&saved_eth, eth, sizeof(saved_eth));

    if (bpf_xdp_adjust_head(ctx, outer_len + 4))
        return XDP_PASS;

    void *data_new = (void *)(long)ctx->data;
    void *data_end_new = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data_new;
    if ((void *)(new_eth + 1) > data_end_new)
        return XDP_PASS;

    new_eth->h_proto = bpf_htons(ETH_P_IP);
    __builtin_memcpy(new_eth->h_dest, saved_eth.h_dest, ETH_ALEN);
    __builtin_memcpy(new_eth->h_source, saved_eth.h_source, ETH_ALEN);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
