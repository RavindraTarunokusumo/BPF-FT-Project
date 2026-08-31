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
int xdp_transform_syn_nrf_l1_005_gtpu_upf_reflector(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    struct gtpuhdr *gtp = (void *)udp + udp_hdr_len;
    if ((void *)(gtp + 1) > data_end)
        return XDP_PASS;

    if (gtp->teid != bpf_htonl(0x12345678))
        return XDP_PASS;

    // Swap MAC addresses
    __u8 tmp = eth->h_source[0]; eth->h_source[0] = eth->h_dest[0]; eth->h_dest[0] = tmp;
    tmp = eth->h_source[1]; eth->h_source[1] = eth->h_dest[1]; eth->h_dest[1] = tmp;
    tmp = eth->h_source[2]; eth->h_source[2] = eth->h_dest[2]; eth->h_dest[2] = tmp;
    tmp = eth->h_source[3]; eth->h_source[3] = eth->h_dest[3]; eth->h_dest[3] = tmp;
    tmp = eth->h_source[4]; eth->h_source[4] = eth->h_dest[4]; eth->h_dest[4] = tmp;
    tmp = eth->h_source[5]; eth->h_source[5] = eth->h_dest[5]; eth->h_dest[5] = tmp;

    // Swap IP addresses
    struct in_addr tmp_ip = ip->src;
    ip->src = ip->dst;
    ip->dst = tmp_ip;

    // Swap UDP ports
    __u16 tmp_port = udp->src;
    udp->src = udp->dest;
    udp->dest = tmp_port;

    // Recalculate checksum
    __u32 csum = 0;
    ip->check = 0;
    __u16 *p = (__u16 *)ip;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        csum += p[i];
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~csum;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
