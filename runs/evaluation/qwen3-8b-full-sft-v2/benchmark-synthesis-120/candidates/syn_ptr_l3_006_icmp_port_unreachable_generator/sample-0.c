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

struct icmphdr_custom {
    __u8 type;
    __u8 code;
    __u16 checksum;
    __u16 data;
};

SEC("xdp")
int xdp_transform_syn_ptr_l3_006_icmp_port_unreachable_generator(struct xdp_md *ctx) {
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(9999)) {
        unsigned char tmp_mac[ETH_ALEN];
        __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

        struct icmphdr_custom *icmp = (void *)(udp + 1);
        if ((void *)(icmp + 1) > data_end)
            return XDP_PASS;

        icmp->type = 3;
        icmp->code = 3;
        icmp->checksum = 0;
        icmp->data = bpf_htons(9999);

        __u32 csum = 0;
        __u16 *p = (__u16 *)icmp;
        #pragma unroll
        for (int i = 0; i < 5; i++)
            csum += p[i];
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        icmp->checksum = ~csum;

        ip->protocol = IPPROTO_ICMP;
        ip->ttl = 64;
        ip->saddr = ip->daddr;
        ip->daddr = 192 + (168 % 256) + (10 % 256) * 256 + (1 % 256) * 256 * 256;

        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
