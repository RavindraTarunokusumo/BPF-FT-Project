#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(eth->h_dest, (void[]){0x02, 0x00, 0x00, 0x00, 0x00, 0x99}, ETH_ALEN);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
