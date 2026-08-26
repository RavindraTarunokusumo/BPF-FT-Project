#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check if packet is at least 14 bytes (Ethernet header size)
    if (data_end - data < 14)
        return XDP_PASS;

    struct ethhdr *eth = data;

    // Check and set each byte of h_dest
    if ((void *)((char *)eth + 0) > data_end) return XDP_PASS;
    eth->h_dest[0] = 0x02;

    if ((void *)((char *)eth + 1) > data_end) return XDP_PASS;
    eth->h_dest[1] = 0x00;

    if ((void *)((char *)eth + 2) > data_end) return XDP_PASS;
    eth->h_dest[2] = 0x00;

    if ((void *)((char *)eth + 3) > data_end) return XDP_PASS;
    eth->h_dest[3] = 0x00;

    if ((void *)((char *)eth + 4) > data_end) return XDP_PASS;
    eth->h_dest[4] = 0x00;

    if ((void *)((char *)eth + 5) > data_end) return XDP_PASS;
    eth->h_dest[5] = 0x99;

    return XDP_PASS;
}
