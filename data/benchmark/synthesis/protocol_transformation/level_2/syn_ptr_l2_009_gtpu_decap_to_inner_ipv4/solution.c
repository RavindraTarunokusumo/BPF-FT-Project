#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct gtpuhdr {
    __u8 flags;
    __u8 msg_type;
    __be16 length;
    __be32 teid;
};

SEC("xdp")
int xdp_gtpu_decap(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    if (ip->ihl != 5)
        return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    struct gtpuhdr *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > data_end)
        return XDP_PASS;

    // Verify inner IPv4 exists
    struct iphdr *inner_ip = (void *)(gtp + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    // Outer IPv4 (20) + UDP (8) + GTP-U (8) = 36 bytes
    if (bpf_xdp_adjust_head(ctx, 36))
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

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
