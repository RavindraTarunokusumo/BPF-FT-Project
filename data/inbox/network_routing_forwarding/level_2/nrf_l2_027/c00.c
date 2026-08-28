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
int xdp_route_nrf_l2_027(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // FAULT: Reading daddr without checking (ip + 1) bounds against data_end
    struct iphdr *ip = (void *)(eth + 1);
    __u8 *d = (void *)&ip->daddr;
    if (d[0] == 10 && d[1] == 0 && d[2] == 27 && d[3] == 1) {
        eth->h_dest[0] = 0x52;
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
