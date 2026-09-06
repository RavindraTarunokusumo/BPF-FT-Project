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
int xdp_transform_ptr_l2_rewrite_ipv4_destination(struct xdp_md *ctx) {
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

    __u32 old_daddr = ip->daddr;
    ip->daddr = bpf_htonl(0xCB007109U);

    // Incremental checksum update for destination address
    __u32 csum = (__u32)ip->check + (old_daddr & 0xFFFF) + (old_daddr >> 16)
                 - ((0xCB007109U & 0xFFFF) + (0xCB007109U >> 16));
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = (__u16)csum;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
