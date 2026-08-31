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
int xdp_transform_syn_ptr_l1_008_dns_id_randomizer(struct xdp_md *ctx) {
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

    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    if (udp->len < (unsigned int)udp_hdr_len)
        return XDP_PASS;

    __u16 *d = (__u16 *)udp + 2;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)d < (void *)udp || (void *)(d + 1) > data_end)
            break;
        __u16 c = *d++;
        *d ^= 0xA55A;
        #pragma unroll
        for (int j = 0; j < 16; j++) {
            if ((void *)d < (void *)udp || (void *)(d + 1) > data_end)
                break;
            __u16 x = *d++;
            __u32 tmp = (__u32)x + 0x1234;
            tmp = (tmp & 0xFFFF) + (tmp >> 16);
            *d = (__u16)tmp;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
