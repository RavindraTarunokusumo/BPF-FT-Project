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
int xdp_transform_syn_ptr_l3_009_mpls_push_dual_label_vpn(struct xdp_md *ctx) {
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

    __u64 len = (__u64)data + (__u64)ctx->data_end - (__u64)data;
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr))
        return XDP_PASS;

    int err = bpf_xdp_adjust_head(ctx, -8);
    if (err)
        return XDP_PASS;

    void *new_data = data;
    struct ethhdr *new_eth = new_data;
    new_eth->h_proto = bpf_htons(0x8847);

    struct mpls_label *mpls = (void *)(new_eth + 1);
    mpls[0].label = 1000;
    mpls[0].bos = 0;
    mpls[0].ttl = 64;

    ip = (void *)(mpls + 1);
    ip->ttl -= 2;  // Decrease TTL for inner IP packet

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
