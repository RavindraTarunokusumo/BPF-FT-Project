#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>
#include <netinet/in.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip > data_end)
        return XDP_PASS;
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;
    uint8_t ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Check TCP header
    struct tcphdr *tcp = data + sizeof(*eth) + ip_hdr_len;
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // Check TCP flags and destination port
    if ((tcp->th_flags & 0x12) == 0x02) {
        uint16_t dport = bpf_ntohs(tcp->dest);
        if (dport >= 1 && dport <= 1023)
            return XDP_DROP;
    }

    return XDP_PASS;
}
