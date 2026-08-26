#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_dns(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if (data_end - data < ETH_HLEN)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (bpf_ntohs(eth->h_proto) != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header bounds
    struct iphdr *ip = data + ETH_HLEN;
    if (data_end - data < ETH_HLEN + 20)
        return XDP_PASS;

    if ((void *)((char *)ip + (ip->ihl * 4)) > data_end)
        return XDP_PASS;

    // Check IP protocol
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Check UDP header bounds
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if (data_end - data < (long)(ETH_HLEN + (ip->ihl * 4) + sizeof(*udp)))
        return XDP_PASS;

    if ((void *)((char *)udp + sizeof(*udp)) > data_end)
        return XDP_PASS;

    // Check destination port
    if (bpf_ntohs(udp->dest) == 53)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
