#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_dnat_tcp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // Check Ethernet header bounds and protocol
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IPv4 header
    ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + 1 > data_end)
        return XDP_PASS;
    if (ip->ihl * 4 > (data_end - (void *)ip))
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
    if ((void *)tcp + 1 > data_end)
        return XDP_PASS;
    if (tcp->doff * 4 > (data_end - (void *)tcp))
        return XDP_PASS;

    // Update destination IP and port
    ip->daddr = bpf_htonl(0xC0A86432);
    tcp->dest = bpf_htons(8080);

    // Recompute IPv4 checksum
    ip->check = 0;
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)((void *)ip);
    __u16 *end = (__u16 *)((void *)ip + (ip->ihl * 4) - 2);
    while (ptr < end) {
        sum += *ptr++;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    ip->check = ~sum;

    // Recompute TCP checksum
    tcp->check = 0;
    __u32 tcp_sum = 0;
    __u16 *tcp_ptr = (__u16 *)((void *)tcp);
    __u16 *tcp_end = (__u16 *)((void *)tcp + (tcp->doff * 4) - 2);
    while (tcp_ptr < tcp_end) {
        tcp_sum += *tcp_ptr++;
    }
    tcp_sum = (tcp_sum & 0xFFFF) + (tcp_sum >> 16);
    tcp->check = ~tcp_sum;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
