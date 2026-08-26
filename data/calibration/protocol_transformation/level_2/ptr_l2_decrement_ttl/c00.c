#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

    // Check IPv4 header bounds
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Check TTL
    if (ip->ttl <= 1)
        return XDP_DROP;

    // Decrement TTL
    ip->ttl--;

    // Update IPv4 checksum
    unsigned int csum = bpf_ntohl(ip->check);
    csum = (csum - 1) & 0xFFFF;
    ip->check = bpf_htonl(csum);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
