#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __u32 vx_flags;
    __u32 vx_vni;
};

SEC("xdp")
int xdp_vxlan_encap_push(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u16 orig_len = (__u16)((void *)data_end - (void *)data);

    if (bpf_xdp_adjust_head(ctx, -50))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *out_eth = data;
    if ((void *)(out_eth + 1) > data_end)
        return XDP_PASS;

    out_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *out_ip = (void *)(out_eth + 1);
    if ((void *)(out_ip + 1) > data_end)
        return XDP_PASS;

    out_ip->version = 4;
    out_ip->ihl = 5;
    out_ip->tos = 0;
    out_ip->tot_len = bpf_htons(orig_len + 36);
    out_ip->id = bpf_htons(0x4321);
    out_ip->frag_off = 0;
    out_ip->ttl = 64;
    out_ip->protocol = IPPROTO_UDP;
    out_ip->saddr = bpf_htonl(0xC0A80101);
    out_ip->daddr = bpf_htonl(0xC0A801FE);
    out_ip->check = 0;

    struct udphdr *out_udp = (void *)(out_ip + 1);
    if ((void *)(out_udp + 1) > data_end)
        return XDP_PASS;

    out_udp->source = bpf_htons(12345);
    out_udp->dest = bpf_htons(4789);
    out_udp->len = bpf_htons(orig_len + 16);
    out_udp->check = 0;

    struct vxlanhdr *out_vx = (void *)(out_udp + 1);
    if ((void *)(out_vx + 1) > data_end)
        return XDP_PASS;

    out_vx->vx_flags = bpf_htonl(0x08000000);
    out_vx->vx_vni = bpf_htonl(100 << 8);

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
