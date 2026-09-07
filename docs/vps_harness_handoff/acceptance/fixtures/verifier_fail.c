#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int verifier_fail(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    return eth->h_proto == bpf_htons(ETH_P_IP) ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
