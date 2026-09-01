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

struct icmphdr_custom {
    __u8 type;
    __u8 code;
    __u16 checksum;
    __u16 id;
};

SEC("xdp")
int xdp_transform_ptr_l3_tcp_dnat(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 old_daddr = ip->daddr;
    ip->daddr = bpf_htonl(0xC0A86432);
    // Recalculate IP checksum
    __u32 csum = 0;
    ip->check = 0;
    __u16 *p = (__u16 *)ip;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        csum += p[i];
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~csum;

    // Recalculate TCP checksum
    struct tcphdr tmp = *tcp;
    tmp.dest = bpf_htons(8080);
    __u32 tmp_csum = 0;
    __u16 *tmp_p = (__u16 *)&tmp;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        tmp_csum += tmp_p[i];
    while (tmp_csum >> 16)
        tmp_csum = (tmp_csum & 0xFFFF) + (tmp_csum >> 16);
    tcp->check = ~tmp_csum;

    *tcp = tmp;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
