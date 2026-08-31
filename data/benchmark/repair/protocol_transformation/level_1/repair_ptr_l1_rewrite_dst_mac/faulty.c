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

    // Compilation error: compound array assignment
    eth->h_dest = (__u8[6]){0x02, 0x00, 0x00, 0x00, 0x00, 0x99};

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
