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
int xdp_v2_ptr_l1_008(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    if (ip->daddr != 1986802630U)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct icmphdr_custom *icmp = (void *)ip + ip_hlen;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type != 8 || icmp->code != 0)
        return XDP_PASS;

    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    __be32 tmp_ip = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp_ip;

    __u32 csum = bpf_ntohs(icmp->checksum) + 0x0800;
    if (csum > 0xFFFF)
        csum = (csum & 0xFFFF) + (csum >> 16);
    icmp->checksum = bpf_htons((__u16)csum);
    icmp->type = 0;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
