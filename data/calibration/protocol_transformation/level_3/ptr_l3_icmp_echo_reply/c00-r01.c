#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("license")
char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IPv4 header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)((char *)ip + ip->ihl * 4) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // Check ICMP header
    struct icmphdr *icmp = data + sizeof(*eth) + sizeof(*ip);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type != 8 || icmp->code != 0)
        return XDP_PASS;

    // Swap Ethernet MAC addresses
    unsigned char temp[ETH_ALEN];
    memcpy(temp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, temp, ETH_ALEN);

    // Swap IPv4 source and destination addresses
    __be32 temp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = temp_ip;

    // Convert ICMP Echo Request to Echo Reply
    icmp->type = 0;

    // Adjust ICMP checksum by +0x0800 (network byte order)
    icmp->checksum = (icmp->checksum + bpf_htons(0x0800)) & 0xFFFF;

    return XDP_TX;
}
