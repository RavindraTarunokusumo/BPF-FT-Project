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
int xdp_transform_ptr_l1_set_source_mac(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if ((void *)(data + sizeof(struct ethhdr)) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    eth->h_source[0] = 0x02;
    eth->h_source[1] = 0x00;
    eth->h_source[2] = 0x00;
    eth->h_source[3] = 0x00;
    eth->h_source[4] = 0x00;
    eth->h_source[5] = 0x42;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
