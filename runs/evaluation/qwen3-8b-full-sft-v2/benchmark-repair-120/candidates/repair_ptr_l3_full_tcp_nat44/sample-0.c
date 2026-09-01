#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __be32 old_src = ip->saddr;
    __be32 new_src = bpf_htonl(0xC6336401);
    ip->saddr = new_src;

    __u16 old_sport = bpf_ntohs(tcp->source);
    tcp->source = bpf_htons(20000);

    // Recalculate checksum
    __u32 csum = 0;
    ip->check = 0;
    __u16 *p = (__u16 *)ip;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        csum += p[i];
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~csum;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
