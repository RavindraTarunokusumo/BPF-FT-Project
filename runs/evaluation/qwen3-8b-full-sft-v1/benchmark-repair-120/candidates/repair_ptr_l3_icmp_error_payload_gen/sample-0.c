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

    if (ip->ttl <= 1) {
        __be32 orig_saddr = ip->saddr;
        ip->daddr = orig_saddr;
        ip->saddr = bpf_htons(0xC0A80101); // Router IP 192.168.1.1

        __u8 tmp_mac[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp_mac[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp_mac[i];
        }

        ip->protocol = IPPROTO_ICMP;
        ip->ttl = 64;

        struct icmphdr *icmp = (void *)(ip + 1);
        if ((void *)(icmp + 1) > data_end)
            return XDP_DROP;

        icmp->type = 11; // Time Exceeded
        icmp->code = 0;
        icmp->checksum = 0;

        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
