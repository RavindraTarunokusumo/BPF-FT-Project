#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int transform_swap_mac(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    unsigned char temporary[ETH_ALEN];

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(temporary, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, temporary, ETH_ALEN);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
