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

    __u8 *d = eth->h_dest;
    d[0] = 0x02;
    d[1] = 0x00;
    d[2] = 0x00;
    d[3] = 0x00;
    d[4] = 0x00;
    d[5] = 0x99;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
