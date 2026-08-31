#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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

    // IP checksum update
    __u32 csum = bpf_ntohs(ip->check);
    __u32 old_hi = bpf_ntohl(old_src) >> 16;
    __u32 old_lo = bpf_ntohl(old_src) & 0xFFFF;
    __u32 new_hi = 0xC633;
    __u32 new_lo = 0x6401;

    csum += old_hi + old_lo;
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((__u16)csum);

    // TCP checksum update for IP change + port change
    __u32 tcpcsum = bpf_ntohs(tcp->check);
    tcpcsum += old_hi + old_lo + old_sport;
    tcpcsum = (tcpcsum & 0xFFFF) + (tcpcsum >> 16);
    tcpcsum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF) + (~20000 & 0xFFFF);
    while (tcpcsum >> 16)
        tcpcsum = (tcpcsum & 0xFFFF) + (tcpcsum >> 16);
    tcp->check = bpf_htons((__u16)tcpcsum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
