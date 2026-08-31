#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
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
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == 8) {
        __u8 tmp_mac[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp_mac[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp_mac[i];
        }

        __be32 tmp_ip = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp_ip;

        icmp->type = 0;
        __u32 csum = bpf_ntohs(icmp->checksum);
        csum += 0x0800;
        if (csum > 0xFFFF)
            csum = (csum & 0xFFFF) + (csum >> 16);
        icmp->checksum = bpf_htons((__u16)csum);

        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
