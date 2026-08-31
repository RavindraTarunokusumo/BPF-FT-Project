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

    __u8 old_tos = ip->tos;
    ip->tos = 0;

    // Incremental checksum update for TOS byte
    __u32 csum = bpf_ntohs(ip->check);
    csum += old_tos;
    if (csum > 0xFFFF)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
