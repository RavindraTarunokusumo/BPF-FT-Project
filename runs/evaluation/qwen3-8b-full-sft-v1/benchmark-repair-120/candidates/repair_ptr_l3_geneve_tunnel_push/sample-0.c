#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    __u64 new_data = (void *)(long)ctx->data - 50;
    if (new_data < (void *)(long)ctx->data - 50 + 50)
        return XDP_DROP;

    if (bpf_xdp_adjust_head(ctx, -50))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    struct iphdr *new_ip = (void *)(new_eth + 1);
    if ((void *)(new_ip + 1) > data_end)
        return XDP_DROP;

    struct udphdr *new_udp = (void *)new_ip + new_ip->ihl * 4;
    if ((void *)(new_udp + 1) > data_end)
        return XDP_DROP;

    struct geneve_hdr *geneve = (void *)new_udp + sizeof(struct udphdr);
    if ((void *)(geneve + 1) > data_end)
        return XDP_DROP;

    // Copy original Ethernet header
    __builtin_memcpy(new_eth, eth, sizeof(struct ethhdr));
    
    // Set new Ethernet header
    new_eth->h_proto = bpf_htons(ETH_P_IP);
    
    // Set new IP header
    __builtin_memcpy(new_ip, ip, sizeof(struct iphdr));
    new_ip->protocol = IPPROTO_UDP;
    new_ip->check = 0;
    __builtin_memcpy(&new_ip->check, &new_ip->check, sizeof(new_ip->check));
    
    // Set new UDP header
    __builtin_memcpy(new_udp, udp, sizeof(struct udphdr));
    new_udp->dest = bpf_htons(6081);
    
    // Set GENEVE header
    geneve->hdr_len = bpf_htons(8 + 20 + 4 + 4 + 4 + 4);
    geneve->reserved = 0;
    geneve->vni = bpf_htons(0x123456);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
