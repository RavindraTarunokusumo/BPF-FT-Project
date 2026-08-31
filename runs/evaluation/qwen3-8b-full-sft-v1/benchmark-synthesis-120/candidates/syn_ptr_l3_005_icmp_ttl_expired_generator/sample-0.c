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
int xdp_transform_syn_ptr_l3_005_icmp_ttl_expired(struct xdp_md *ctx) {
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

    if (ip->ttl > 1)
        return XDP_PASS;

    unsigned char tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct iphdr *new_ip = (void *)ip;
    new_ip->ttl = 64;
    new_ip->protocol = IPPROTO_ICMP;

    unsigned int csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        csum += ((unsigned char *)new_ip)[i];
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    new_ip->check = ~csum + 0x10000;

    struct icmphdr *icmp = (void *)(new_ip + 1);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;
    icmp->type = 11;
    icmp->code = 0;
    icmp->checksum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        csum += ((unsigned char *)icmp)[i];
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    icmp->checksum = ~csum + 0x10000;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
