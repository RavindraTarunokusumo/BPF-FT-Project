#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

    struct bpf_fib_lookup fib_params = {
        .family = AF_INET,
        .ipv4_src = ip->saddr,
        .ipv4_dst = ip->daddr,
        .ifindex = ctx->ingress_ifindex,
    };

    __u32 rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = fib_params.dmac[i];
            eth->h_source[i] = fib_params.smac[i];
        }
        return bpf_redirect(fib_params.ifindex, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
