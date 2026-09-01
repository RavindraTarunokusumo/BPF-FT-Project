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
int xdp_transform_syn_ptr_l3_007_geneve_metadata_insertion(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    struct genevehdr *gen = (void *)(udp + 1);
    if ((void *)(gen + 1) > data_end)
        return XDP_PASS;

    if (gen->opt_len != 0)
        return XDP_PASS;

    int res = bpf_xdp_adjust_head(ctx, -8);
    if (res < 0)
        return XDP_PASS;

    __u8 *opt = (void *)gen + gen->hdr_len;
    if ((void *)(opt + 2) > data_end)
        return XDP_PASS;

    gen->opt_len = 2;
    udp->len += 8;

    opt[0] = 0x01;
    opt[1] = 0x00;
    opt[2] = 0xDE;
    opt[3] = 0xAD;
    opt[4] = 0xBE;
    opt[5] = 0xEF;
    opt[6] = 0x00;
    opt[7] = 0x00;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
