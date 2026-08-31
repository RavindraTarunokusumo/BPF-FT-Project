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
int xdp_transform_syn_ptr_l2_004_gre_decap_to_inner_ipv4(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    __u8 *p = (void *)(ip + 1);
    if ((void *)(p + 20) > data_end)
        return XDP_PASS;

    struct grehdr *gre = (void *)p;
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    if (gre->flags != 0)
        return XDP_PASS;

    __u8 *new_data = (void *)(eth + 1) + 20 + 4;
    if (new_data > data_end)
        return XDP_PASS;

    __builtin_memcpy(new_data, eth, 14);
    struct ethhdr *new_eth = new_data;
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    __u64 len = (__u64)data_end - (__u64)ip - 20 - 4;
    if (len < sizeof(struct iphdr))
        return XDP_PASS;

    __builtin_memcpy(new_eth + 1, ip, len);
    
    int res = bpf_xdp_adjust_head(ctx, 24);
    if (res < 0)
        return XDP_PASS;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
