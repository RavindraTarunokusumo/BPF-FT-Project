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
    __be32 new_dst = bpf_htonl(0x0A0A0A0A);
    ip->daddr = new_dst;

    /* Pseudo-header delta components (1's complement arithmetic) */
    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0x0A0A;
    __u32 new_lo = 0x0A0A;

    /* Correct delta: (new - old) wrapped to 16 bits */
    __s32 delta_hi = (new_hi - old_hi) & 0xFFFF;
    __s32 delta_lo = (new_lo - old_lo) & 0xFFFF;

    /* Fold the 16-bit delta into the existing TCP checksum */
    __u32 tcpcsum = bpf_ntohs(tcp->check);
    tcpcsum += delta_hi;
    tcpcsum += delta_lo;
    while (tcpcsum >> 16)
        tcpcsum = (tcpcsum & 0xFFFF) + (tcpcsum >> 16);
    tcp->check = bpf_htons((__u16)tcpcsum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
