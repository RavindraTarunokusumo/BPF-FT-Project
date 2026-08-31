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
int xdp_transform_syn_ptr_l3_006_icmp_port_unreachable(struct xdp_md *ctx) {
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

    if (udp->dest != bpf_htons(9999))
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

    ip->protocol = IPPROTO_ICMP;

    unsigned int new_hdr_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    if ((void *)ip + ip_hdr_len + sizeof(struct icmphdr) > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_hdr_len;
    icmp->type = 3;
    icmp->code = 3;
    icmp->checksum = 0;
    icmp->un.echo.icmp_id = 0x1234;
    icmp->un.echo.icmp_seq = 0x5678;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++)
        csum += ((__u16 *)icmp)[i];
    icmp->checksum = (__u16)csum + (csum >> 16);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
