#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct grehdr {
    __be16 flags;
    __be16 proto;
};

SEC("xdp")
int xdp_gre_encap_push(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u16 orig_ip_len = (__u16)((void *)data_end - (void *)(eth + 1));

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    if (bpf_xdp_adjust_head(ctx, -24))
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

    struct iphdr *out_ip = (void *)(new_eth + 1);
    if ((void *)(out_ip + 1) > data_end)
        return XDP_PASS;

    out_ip->version = 4;
    out_ip->ihl = 5;
    out_ip->tos = 0;
    out_ip->tot_len = bpf_htons(orig_ip_len + 24);
    out_ip->id = bpf_htons(0x5678);
    out_ip->frag_off = 0;
    out_ip->ttl = 64;
    out_ip->protocol = 47; // IPPROTO_GRE
    out_ip->saddr = bpf_htonl(0xC0A80101);
    out_ip->daddr = bpf_htonl(0xC0A801FE);
    out_ip->check = 0;

    struct grehdr *gre = (void *)(out_ip + 1);
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    gre->flags = 0;
    gre->proto = bpf_htons(ETH_P_IP);

    __u16 *words = (void *)out_ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    out_ip->check = bpf_htons((~csum) & 0xFFFF);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
