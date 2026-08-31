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
int xdp_transform_syn_ptr_l3_008_gtpu_teid_remapping_and_csum(struct xdp_md *ctx) {
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

    unsigned int udp_hdr_len = ip_hdr_len + sizeof(struct udphdr);
    if ((void *)ip + udp_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    unsigned int gtp_hdr_len = udp_hdr_len + sizeof(struct gtpuhdr);
    if ((void *)udp + gtp_hdr_len > data_end)
        return XDP_PASS;

    struct gtpuhdr *gtp = (void *)udp + udp_hdr_len;
    __u32 teid = gtp->teid;
    if (teid != bpf_htonl(0x1000))
        return XDP_PASS;

    gtp->teid = bpf_htonl(0x2000);
    ip->daddr = bpf_htonl(0xC6336401);

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

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
