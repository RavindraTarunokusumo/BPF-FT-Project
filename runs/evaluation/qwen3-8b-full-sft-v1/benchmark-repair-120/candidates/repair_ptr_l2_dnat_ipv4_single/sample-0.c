#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htonl(0xCB007109);
    ip->daddr = new_dst;

    // Incremental csum update
    __u32 csum = bpf_ntohs(ip->check);
    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0xCB00;
    __u32 new_lo = 0x7109;

    csum += (old_hi + old_lo) - (new_hi + new_lo);
    while (csum >= 0x10000)
        csum -= 0x10000;
    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
