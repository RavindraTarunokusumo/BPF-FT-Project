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

struct genevehdr {
    __u32 flags;
    __u32 len;
    __u32 protocol;
    __u32 opt_len;
    __u32 opt_ptr;
};

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

    if (bpf_xdp_adjust_head(ctx, -8) < 0)
        return XDP_PASS;

    unsigned char *opt_ptr = (void *)gen + sizeof(*gen);
    __builtin_memcpy(opt_ptr, "\x01\x00\x01\x04\xDE\xAD\xBE\xEF", 8);

    gen->opt_len = bpf_htons(2);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
