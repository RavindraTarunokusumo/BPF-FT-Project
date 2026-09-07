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
int xdp_transform_syn_ptr_l2_002_nat64_stateless_translator(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ipv6 = (void *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return XDP_PASS;

    __u8 *d = (void *)&ipv6->daddr;
    if (d[0] == 0x64 && d[1] == 0xFF && d[2] == 0x9B) {
        __u32 ipv4_dst = (__u32)d[12] | ((__u32)d[13] << 8) | ((__u32)d[14] << 16) | ((__u32)d[15] << 24);
        
        struct iphdr *new_ip = (void *)ipv6;
        if ((void *)(new_ip + 1) > data_end)
            return XDP_PASS;
        
        __u8 *s = (void *)&ipv6->saddr;
        new_ip->saddr = ipv4_dst;
        new_ip->daddr = 0;
        new_ip->ttl = 64;
        new_ip->protocol = IPPROTO_ICMP;
        new_ip->check = 0;
        // Simple incremental checksum adjustment
        __u32 csum = (__u32)new_ip->check + 0x0100;
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        new_ip->check = (__u16)csum;
        
        eth->h_proto = bpf_htons(ETH_P_IP);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
