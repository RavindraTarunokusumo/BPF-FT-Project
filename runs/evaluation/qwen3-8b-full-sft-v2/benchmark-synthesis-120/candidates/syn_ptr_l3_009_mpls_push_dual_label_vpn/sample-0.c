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
    __be32 label;
    __u8  tc;
    __u8  ttl;
    __u8  bos;
    __u8  pad[3];
};

SEC("xdp")
int xdp_transform_syn_ptr_l3_009_mpls_push_dual_label_vpn(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, -8))
        return XDP_PASS;

    struct mpls_hdr *mpls = (void *)(eth + 1);
    mpls->label = bpf_htons(1000);
    mpls->tc = 0;
    mpls->ttl = 64;
    mpls->bos = 0;
    __u8 *pad = (void *)(mpls + 1);
    pad[0] = 0;
    pad[1] = 0;
    pad[2] = 0;
    pad[3] = 0;

    mpls = (void *)(mpls + 1);
    mpls->label = bpf_htons(200);
    mpls->tc = 0;
    mpls->ttl = 64;
    mpls->bos = 1;
    pad = (void *)(mpls + 1);
    pad[0] = 0;
    pad[1] = 0;
    pad[2] = 0;
    pad[3] = 0;

    eth->h_proto = bpf_htons(0x8847);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
