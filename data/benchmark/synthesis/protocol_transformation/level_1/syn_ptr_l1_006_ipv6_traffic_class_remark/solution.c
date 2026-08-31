#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

SEC("xdp")
int xdp_ipv6_remark(struct xdp_md *ctx) {
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

    __u32 *vcf = (void *)ip6;
    __u32 orig = bpf_ntohl(*vcf);
    __u32 updated = (orig & ~0x0FF00000) | (0xB8U << 20);
    *vcf = bpf_htonl(updated);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
