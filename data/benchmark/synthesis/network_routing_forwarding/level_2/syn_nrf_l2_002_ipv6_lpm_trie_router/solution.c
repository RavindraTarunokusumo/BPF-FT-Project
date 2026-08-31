#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

SEC("xdp")
int xdp_ipv6_lpm_router(struct xdp_md *ctx) {
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

    __u16 *daddr_words = (void *)&ip6->daddr;
    // Check 2001:db8:1::/48 (0x2001, 0x0db8, 0x0001)
    if (daddr_words[0] == bpf_htons(0x2001) && daddr_words[1] == bpf_htons(0x0DB8) && daddr_words[2] == bpf_htons(0x0001))
        return bpf_redirect(10, 0);

    // Check 2001:db8:2::/48 (0x2001, 0x0db8, 0x0002)
    if (daddr_words[0] == bpf_htons(0x2001) && daddr_words[1] == bpf_htons(0x0DB8) && daddr_words[2] == bpf_htons(0x0002))
        return bpf_redirect(11, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
