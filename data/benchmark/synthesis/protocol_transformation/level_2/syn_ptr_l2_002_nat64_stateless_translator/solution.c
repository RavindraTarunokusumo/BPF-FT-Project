#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_nat64_stateless(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    __u32 *daddr_words = (__u32 *)&ip6->daddr;
    if (daddr_words[0] != bpf_htonl(0x0064FF9B) || daddr_words[1] != 0 || daddr_words[2] != 0)
        return XDP_PASS;

    __be32 ipv4_dst = daddr_words[3];
    __u8 proto = ip6->nexthdr;
    __u16 payload_len = bpf_ntohs(ip6->payload_len);

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    if (bpf_xdp_adjust_head(ctx, 20))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *ip4 = (void *)(new_eth + 1);
    if ((void *)(ip4 + 1) > data_end)
        return XDP_PASS;

    ip4->version = 4;
    ip4->ihl = 5;
    ip4->tos = 0;
    ip4->tot_len = bpf_htons(20 + payload_len);
    ip4->id = bpf_htons(0x1234);
    ip4->frag_off = 0;
    ip4->ttl = 64;
    ip4->protocol = proto;
    ip4->saddr = bpf_htonl(0xC0A80101);
    ip4->daddr = ipv4_dst;
    ip4->check = 0;

    __u16 *words = (void *)ip4;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip4->check = bpf_htons((~csum) & 0xFFFF);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
