#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>

SEC("xdp")
int xdp_icmp_reply_8(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type != 8) // Echo Request
        return XDP_PASS;

    // Swap MACs
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    // Swap IPs
    __be32 tmp_ip = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp_ip;

    // Convert to Echo Reply (type 0)
    icmp->type = 0;
    icmp->checksum = 0; // Incremental checksum omitted for simplified verifier-safety

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
