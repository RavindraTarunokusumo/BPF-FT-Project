#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip > data_end)
        return XDP_PASS;

    u_int8_t ihl = ip->ihl;
    if (ihl < 5 || ihl > 15)
        return XDP_PASS;

    int ip_header_len = ihl * 4;
    if (data + sizeof(*eth) + ip_header_len > data_end)
        return XDP_PASS;

    // Check protocol is ICMP
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // Check ICMP header
    struct icmphdr *icmp = data + sizeof(*eth) + ip_header_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == 8)
        return XDP_DROP;

    return XDP_PASS;
}
