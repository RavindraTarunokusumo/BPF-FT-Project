#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_rewrite_udp_port(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)((char *)eth + ETH_HLEN) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IPv4 header
    struct iphdr *ip = data + ETH_HLEN;
    int ip_len = ip->ihl * 4;
    if ((void *)((char *)ip + ip_len) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Check UDP header
    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)((char *)udp + sizeof(*udp)) > data_end)
        return XDP_PASS;

    // Modify destination port and adjust checksum
    __u16 old_dest = ntohs(udp->dest);
    udp->dest = bpf_htons(5353);
    int delta = old_dest - 5353;
    if (udp->check != 0) {
        udp->check = (udp->check + delta) & 0xffff;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
