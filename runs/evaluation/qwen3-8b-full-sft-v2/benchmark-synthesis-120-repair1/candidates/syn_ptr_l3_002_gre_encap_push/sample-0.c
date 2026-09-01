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

struct grehdr {
    __be32 flags;
    __be32 proto;
};

SEC("xdp")
int xdp_transform_syn_ptr_l3_002_gre_encap_push(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_DROP;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    int res = bpf_xdp_adjust_head(ctx, -24);
    if (res < 0)
        return XDP_DROP;

    struct ethhdr *new_eth = data;
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *new_ip = (void *)(new_eth + 1);
    __u8 *p = (void *)new_ip + sizeof(struct iphdr);
    __builtin_memcpy(p, ip, sizeof(struct iphdr));
    ip = new_ip;

    ip->protocol = 47;
    ip->check = 0;
    ip->check = bpf_csum_diff(0, 0, sizeof(struct iphdr), ip, 0);

    ip->saddr = bpf_htons(0x118A10C0);
    ip->daddr = bpf_htons(0x118A10F4);

    struct grehdr *gre = (void *)ip + sizeof(struct iphdr);
    gre->flags = 0;
    gre->proto = bpf_htons(0x0800);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";