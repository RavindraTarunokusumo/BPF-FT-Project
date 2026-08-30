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

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u8 *src = eth->h_source;
    if (src + 6 <= data_end) {
        __u8 *new_src = src;
        new_src[0] = 0x02;
        new_src[1] = 0x00;
        new_src[2] = 0x00;
        new_src[3] = 0x00;
        new_src[4] = 0x00;
        new_src[5] = 0x42;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
<|im_end|>
