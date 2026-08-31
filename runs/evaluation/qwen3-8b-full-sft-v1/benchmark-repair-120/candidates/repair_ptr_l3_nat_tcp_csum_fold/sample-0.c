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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htons(0x0A0A0A0A);
    ip->daddr = new_dst;

    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0x0A0A;
    __u32 new_lo = 0x0A0A;

    __u32 ipcheck = bpf_ntohl(ip->check);
    // Adjust pseudo-header checksum for IP address change
    ipcheck += (new_hi + new_lo) - (old_hi + old_lo);
    while (ipcheck >> 16)
        ipcheck += ipcheck >> 16;
    ip->check = bpf_htons((__u16)ipcheck);

    __u32 tcpcsum = bpf_ntohs(tcp->check);
    // Adjust TCP checksum for IP address change
    tcpcsum += (new_hi + new_lo) - (old_hi + old_lo);
    while (tcpcsum >> 16)
        tcpcsum += tcpcsum >> 16;
    tcp->check = bpf_htons((__u16)tcpcsum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
