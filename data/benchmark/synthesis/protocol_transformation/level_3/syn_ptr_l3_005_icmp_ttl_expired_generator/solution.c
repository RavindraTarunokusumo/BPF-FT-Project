#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

SEC("xdp")
int xdp_icmp_time_exceeded(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    unsigned char tmp_mac[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac[i] = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp_mac[i];
    }

    __be32 src = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = src;
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;

    __u16 *ip_words = (void *)ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(ip_words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(ip_words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((~csum) & 0xFFFF);

    struct icmphdr *icmp = (void *)(ip + 1);
    if ((void *)(icmp + 1) <= data_end) {
        icmp->type = 11;
        icmp->code = 0;
        icmp->checksum = 0;
        __u16 *icmp_words = (void *)icmp;
        __u32 icmp_csum = 0;
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if ((void *)(icmp_words + i + 1) <= data_end)
                icmp_csum += bpf_ntohs(icmp_words[i]);
        }
        while (icmp_csum >> 16)
            icmp_csum = (icmp_csum & 0xFFFF) + (icmp_csum >> 16);
        icmp->checksum = bpf_htons((~icmp_csum) & 0xFFFF);
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
