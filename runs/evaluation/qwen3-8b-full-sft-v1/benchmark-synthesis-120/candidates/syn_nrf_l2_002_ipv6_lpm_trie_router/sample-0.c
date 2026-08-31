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
int xdp_route_syn_nrf_l2_002(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    __u8 *d = (void *)&ip6->daddr;
    if (d < (void *)ip6 + sizeof(struct ipv6hdr))
        return XDP_PASS;

    if (d[0] == 0x20 && d[1] == 0x01 && d[2] == 0xdb && d[3] == 0x8 &&
        d[4] == 0x1 && d[5] == 0 && d[6] == 0 && d[7] == 0 &&
        d[8] == 0 && d[9] == 0 && d[10] == 0 && d[11] == 0 &&
        d[12] == 0 && d[13] == 0 && d[14] == 0 && d[15] == 0)
        return bpf_redirect(10, 0);

    if (d[0] == 0x20 && d[1] == 0x01 && d[2] == 0xdb && d[3] == 0x8 &&
        d[4] == 0x2 && d[5] == 0 && d[6] == 0 && d[7] == 0 &&
        d[8] == 0 && d[9] == 0 && d[10] == 0 && d[11] == 0 &&
        d[12] == 0 && d[13] == 0 && d[14] == 0 && d[15] == 0)
        return bpf_redirect(11, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
