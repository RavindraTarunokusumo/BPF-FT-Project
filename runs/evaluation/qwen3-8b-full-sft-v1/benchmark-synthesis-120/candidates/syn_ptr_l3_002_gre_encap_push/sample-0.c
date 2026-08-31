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
    __u8  hdr_len;
    __u8  csum;
    __u16 proto;
    __u32 csum_val;
};

SEC("xdp")
int xdp_transform_syn_ptr_l3_002_gre_encap_push(struct xdp_md *ctx) {
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

    __u64 len = (__u64)data + (__u64)data_end - (__u64)data;
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr))
        return XDP_PASS;

    __u32 adj = 24;
    if ((void *)ip - adj < data)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, -adj))
        return XDP_PASS;

    struct ethhdr *new_eth = data;
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *new_ip = (void *)(new_eth + 1);
    __u8 *p = (void *)(new_ip + 1);

    new_ip->protocol = IPPROTO_GRE;
    new_ip->ttl = 64;
    new_ip->check = 0;
    new_ip->saddr = inet_addr("192.168.1.1");
    new_ip->daddr = inet_addr("192.168.1.254");

    #pragma unroll
    for (int i = 0; i < 16; i++)
        new_ip->check += ( (__u16)new_ip[i] & 0xFFFF );
    while (new_ip->check >> 16)
        new_ip->check = (new_ip->check & 0xFFFF) + (new_ip->check >> 16);

    struct grehdr *gre = (void *)(new_ip + 1);
    gre->hdr_len = 4;
    gre->csum = 1;
    gre->proto = bpf_htons(0x0800);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
