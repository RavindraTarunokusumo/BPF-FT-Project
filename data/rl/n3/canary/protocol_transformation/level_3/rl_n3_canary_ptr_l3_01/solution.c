#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>

SEC("xdp")
int xdp_decap_4in6_canary(struct xdp_md *ctx) {
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

    if (ip6->nexthdr == 4) {
        struct ethhdr eth_backup;
        __builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));
        eth_backup.h_proto = bpf_htons(ETH_P_IP);

        if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct ipv6hdr)))
            return XDP_DROP;

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_DROP;

        __builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
