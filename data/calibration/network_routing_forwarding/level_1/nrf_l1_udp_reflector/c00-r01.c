#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_udp_reflector(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip > data_end)
        return XDP_PASS;

    if (ip->ihl < 5)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Check UDP header
    struct udphdr *udp = data + sizeof(*eth) + (ip->ihl * 4);
    if ((void *)((char *)udp + sizeof(*udp)) > data_end)
        return XDP_PASS;

    // Swap MAC addresses
    struct ethhdr *eth_hdr = data;
    __u8 temp;
    temp = eth_hdr->h_source[0];
    eth_hdr->h_source[0] = eth_hdr->h_dest[0];
    eth_hdr->h_dest[0] = temp;

    temp = eth_hdr->h_source[1];
    eth_hdr->h_source[1] = eth_hdr->h_dest[1];
    eth_hdr->h_dest[1] = temp;

    temp = eth_hdr->h_source[2];
    eth_hdr->h_source[2] = eth_hdr->h_dest[2];
    eth_hdr->h_dest[2] = temp;

    temp = eth_hdr->h_source[3];
    eth_hdr->h_source[3] = eth_hdr->h_dest[3];
    eth_hdr->h_dest[3] = temp;

    temp = eth_hdr->h_source[4];
    eth_hdr->h_source[4] = eth_hdr->h_dest[4];
    eth_hdr->h_dest[4] = temp;

    temp = eth_hdr->h_source[5];
    eth_hdr->h_source[5] = eth_hdr->h_dest[5];
    eth_hdr->h_dest[5] = temp;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
