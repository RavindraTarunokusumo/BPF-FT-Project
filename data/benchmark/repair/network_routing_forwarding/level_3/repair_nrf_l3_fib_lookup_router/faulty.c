#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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

    // Compilation error: struct bpf_fib_lookup incomplete
    struct bpf_fib_lookup fib_params = {0};
    fib_params.family = 2; // AF_INET
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == 0) {
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
