#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct ipv6hdr {
    __be32 vtcf;
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    ip6->saddr[0] = 0xFD;
    ip6->saddr[1] = 0x00;
    ip6->saddr[2] = 0x00;
    ip6->saddr[3] = 0x99;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
