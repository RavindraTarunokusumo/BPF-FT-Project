#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


SEC("xdp")
int xdp_router_nrf_l3_fib(struct xdp_md *ctx) {
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

    if (ip->ttl <= 1)
        return XDP_PASS;

    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET;
    fib_params.ipv4.src = ip->saddr;
    fib_params.ipv4.dst = ip->daddr;
    fib_params.protocol = ip->protocol;
    fib_params.tot_len = (__u32)ip->tot_len;
    fib_params.ifindex = ctx->ingress_ifindex;

    __u32 ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
        return XDP_PASS;
    }

    ip->ttl -= 1;
    __u32 csum = (__u32)ip->check + 0x0100;
    ip->check = (__u16)csum + (__u16)csum >> 16;

    if (fib_params.dmac) {
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        if (fib_params.smac) {
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        }
    }

    return bpf_redirect(fib_params.ifindex, 0);
}

char _license[] SEC("license") = "GPL";
<|im_end|>
