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
    __be16 checksum;
    __be16 id;
    __be16 sequence;
};

SEC("xdp")
int xdp_transform_syn_ptr_l3_005_icmp_ttl_expired_generator(struct xdp_md *ctx) {
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

    if (ip->ttl <= 1) {
        unsigned char tmp_mac[ETH_ALEN];
        __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

        __u8 tmp_proto = ip->protocol;
        ip->protocol = IPPROTO_ICMP;
        ip->ttl = 64;

        struct icmphdr_custom *icmp = (void *)(ip + 1);
        icmp->type = 11;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->id = bpf_htons(1234);
        icmp->sequence = bpf_htons(5678);

        __u32 csum = 0;
        ip->check = 0;
        __u16 *p = (__u16 *)ip;
        #pragma unroll
        for (int i = 0; i < 10; i++)
            csum += p[i];
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = ~csum;

        icmp->checksum = bpf_htons((__u16)csum);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";