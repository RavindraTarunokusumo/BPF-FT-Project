#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    __u64 hdr_len = (void *)(ip + 1) - (void *)ip;
    if (hdr_len < sizeof(struct iphdr) + sizeof(struct gre_hdr))
        return XDP_PASS;

    struct gre_hdr *gre = (void *)ip + sizeof(struct iphdr);
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;
    if (gre->protocol != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u64 new_hdr_len = (void *)&gre->c - (void *)ip;
    if (new_hdr_len > data_end - data)
        return XDP_DROP;

    struct ethhdr *new_eth = data;
    __builtin_memcpy(new_eth, eth, sizeof(struct ethhdr));
    struct iphdr *new_ip = (void *)new_eth + sizeof(struct ethhdr);
    __builtin_memcpy(new_ip, ip, (void *)(gre + 1) - (void *)ip);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
