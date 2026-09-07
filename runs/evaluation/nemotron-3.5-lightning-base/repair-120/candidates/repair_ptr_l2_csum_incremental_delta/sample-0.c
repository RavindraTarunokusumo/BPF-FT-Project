#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htonl(0x0A000063);
    ip->daddr = new_dst;

    __u32 csum = bpf_ntohs(ip->check);
    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0x0A00;
    __u32 new_lo = 0x0063;

    // RFC 1624 incremental update:
    // Subtract old IP parts and add new IP parts.
    csum += old_hi + old_lo;
    csum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);

    // Fold carry bits: add upper 16 bits to lower 16 bits until no carry remains.
    while (csum >> 16) {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }

    // Take one's complement of the final sum to get the checksum.
    ip->check = bpf_htons((__u16)(~csum));

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
