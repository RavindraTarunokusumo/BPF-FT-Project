#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
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
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IPv4 header
    ip = data + sizeof(*eth);
    if (ip + 1 > data_end)
        return XDP_PASS;
    if (ip->ihl * 4 > data_end - ip)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    tcp = ip + (ip->ihl * 4);
    if (tcp + 1 > data_end)
        return XDP_PASS;
    if (tcp->doff * 4 > data_end - tcp)
        return XDP_PASS;

    // Update destination IP and port
    ip->daddr = bpf_htonl(0xC0A86432);
    tcp->dest = bpf_htons(8080);

    // Recompute IPv4 checksum
    ip->check = 0;
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)((void *)ip + offsetof(struct iphdr, ihl));
    __u16 *end = (__u16 *)((void *)ip + offsetof(struct iphdr, check));
    while (ptr < end) {
        sum += *ptr++;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    ip->check = ~sum;

    // Recompute TCP checksum
    tcp->check = 0;
    __u32 tcp_sum = 0;
    __u16 *tcp_ptr = (__u16 *)((void *)tcp + offsetof(struct tcphdr, source));
    __u16 *tcp_end = (__u16 *)((void *)tcp + offsetof(struct tcphdr, urg_ptr));
    while (tcp_ptr < tcp_end) {
        tcp_sum += *tcp_ptr++;
    }
    tcp_sum = (tcp_sum & 0xFFFF) + (tcp_sum >> 16);
    tcp->check = ~tcp_sum;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
