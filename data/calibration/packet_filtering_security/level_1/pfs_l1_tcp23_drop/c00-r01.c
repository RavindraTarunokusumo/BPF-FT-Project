#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_telnet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if ((unsigned int)(data_end - data) < sizeof(struct ethhdr))
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header bounds
    struct iphdr *ip = data + sizeof(struct ethhdr);
    __u32 ip_header_len = ip->ihl * 4;
    if ((unsigned int)(data_end - data) < sizeof(struct ethhdr) + ip_header_len)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Check TCP header bounds
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + ip_header_len;
    __u32 tcp_header_len = tcp->doff * 4;
    if ((unsigned int)(data_end - data) < sizeof(struct ethhdr) + ip_header_len + tcp_header_len)
        return XDP_PASS;

    // Check destination port
    if (tcp->dest == bpf_htons(23))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
