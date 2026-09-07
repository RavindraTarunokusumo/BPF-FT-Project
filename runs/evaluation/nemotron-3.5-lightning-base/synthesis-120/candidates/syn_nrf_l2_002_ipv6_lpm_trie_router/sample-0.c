#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/ctx/sk_buff.h>

/* XDP program entry point */
SEC("xdp")
int xdp_ipv6_lpm_router(struct bpf_program *prog, struct bpf_context *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct ipv6hdr *ip6;

    /* 1. Validate Ethernet frame bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Verify EtherType == IPv6 (0x86DD) */
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    /* 3. Validate IPv6 header bounds */
    if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
        return XDP_PASS;

    ip6 = data + sizeof(*eth);

    /* 4. Match destination prefix 2001:db8:1::/48 -> ifindex 10 */
    if (ip6->daddr.s6_addr32[0] == bpf_htonl(0x20010db8) &&
        ip6->daddr.s6_addr32[1] == bpf_htonl(0x00010000) &&
        ip6->daddr.s6_addr32[2] == bpf_htonl(0x00000000)) {
        bpf_redirect(10, 0);
        return XDP_PASS; /* redirect was issued, still return PASS */
    }

    /* 5. Match destination prefix 2001:db8:2::/48 -> ifindex 11 */
    if (ip6->daddr.s6_addr32[0] == bpf_htonl(0x20010db8) &&
        ip6->daddr.s6_addr32[1] == bpf_htonl(0x00020000) &&
        ip6->daddr.s6_addr32[2] == bpf_htonl(0x00000000)) {
        bpf_redirect(11, 0);
        return XDP_PASS; /* redirect was issued, still return PASS */
    }

    /* 6. Pass unrouted destinations and non-matching traffic */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
