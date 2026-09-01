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
int xdp_route_syn_nrf_l2_008_ip_in_ip_tunnel_router(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_IP)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)ip + ip->ihl * 4;
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    __u8 *d = (void *)&inner_ip->daddr;
    if (d[0] == 10 && d[1] == 1 && d[2] == 0 && d[3] <= 255)
        return bpf_redirect(18, 0);

    if (d[0] == 10 && d[1] == 2 && d[2] == 0 && d[3] <= 255)
        return bpf_redirect(19, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";