#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header bounds
    void *ip_start = data + sizeof(struct ethhdr);
    if (ip_start + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = ip_start;
    if (ip->version != 4 || ip->ihl < 5 || ip->ihl > 15)
        return XDP_PASS;

    int ip_header_len = ip->ihl * 4;
    if (ip_start + ip_header_len > data_end)
        return XDP_PASS;

    // Check ICMP protocol
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // Check ICMP header bounds
    void *icmp_start = ip_start + ip_header_len;
    if (icmp_start + sizeof(struct icmphdr) > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = icmp_start;

    // Swap Ethernet source and destination MAC addresses
    uint8_t temp[ETH_ALEN];
    for (int i = 0; i < ETH_ALEN; i++) {
        temp[i] = eth->h_source[i];
    }
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_source[i] = eth->h_dest[i];
    }
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_dest[i] = temp[i];
    }

    return XDP_TX;
}
