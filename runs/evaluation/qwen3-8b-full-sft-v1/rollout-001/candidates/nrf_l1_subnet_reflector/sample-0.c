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
int xdp_route_nrf_l1_subnet_reflector(struct xdp_md *ctx) {
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

    __u8 *d = (void *)&ip->daddr;
    if (d[0] == 0xC0 && d[1] == 0x00 && d[2] == 0x02 && d[3] == 0x80)
        return XDP_PASS;

    // Swap source and destination MAC addresses
    struct ethhdr tmp = *eth;
    eth->h_dest = eth->h_source;
    eth->h_source = tmp.h_source;
    
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
<|im_end|>
