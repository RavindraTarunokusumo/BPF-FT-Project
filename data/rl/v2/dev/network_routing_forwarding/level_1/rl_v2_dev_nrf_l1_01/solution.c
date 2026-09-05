#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_fwd_ttl_1(struct xdp_md *ctx) {
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

    if (ip->ttl <= 1)
        return XDP_DROP;

    ip->ttl -= 1;
    ip->check = 0;

    __u16 *words = (void *)ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((~csum) & 0xFFFF);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
