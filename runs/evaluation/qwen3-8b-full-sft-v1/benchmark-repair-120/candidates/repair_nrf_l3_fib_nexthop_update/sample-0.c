#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_fib_lookup {
    __u8 family;
    __u8 l4_protocol;
    __be16 sport;
    __be16 dport;
    __u32 ifindex;
    __u8 dmac[ETH_ALEN];
    __u8 smac[ETH_ALEN];
    union {
        __be32 ipv4_src;
        __u8 ipv6_src[16];
    };
    union {
        __be32 ipv4_dst;
        __u8 ipv6_dst[16];
    };
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
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

    struct bpf_fib_lookup fib_params = {0};
    fib_params.family = bpf_htons(AF_INET);
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;
    __builtin_memcpy(fib_params.dmac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(fib_params.smac, eth->h_source, ETH_ALEN);

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == 0) {
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        return bpf_redirect(fib_params.ifindex, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
