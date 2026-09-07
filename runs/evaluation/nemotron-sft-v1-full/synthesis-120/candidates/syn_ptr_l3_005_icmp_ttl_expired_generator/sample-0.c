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

        __builtin_memcpy(&ip->daddr, &ip->saddr, sizeof(ip->daddr));
        ip->saddr = tmp_mac[0]; // placeholder, will be fixed below

        ip->ttl = 64;
        ip->protocol = IPPROTO_ICMP;

        unsigned char *icmp_ptr = (void *)(ip + 1);
        if ((void *)(icmp_ptr + sizeof(struct icmphdr)) > data_end)
            return XDP_PASS;

        struct icmphdr *icmp = (void *)icmp_ptr;
        icmp->type = 11;
        icmp->code = 0;
        // Recalculate checksum
        __u32 csum = 0;
        __u16 *p = (__u16 *)icmp;
        #pragma unroll
        for (int i = 0; i < 10; i++)
            csum += p[i];
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        icmp->checksum = ~csum;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
