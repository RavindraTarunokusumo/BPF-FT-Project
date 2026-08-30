#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/byteorder/generic.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int pfs_l1_tcp23_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Check Ethernet protocol is IPv4 (ETH_P_IP)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IPv4 header
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Check IP protocol is TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Check IP header length (IHL) is valid
    u8 ihl = ip->ihl;
    if (ihl < 5 || ihl > 15)
        return XDP_PASS;

    // Check that the IP header is within the packet
    if ((void *)ip + (ihl * 4) > data_end)
        return XDP_PASS;

    // TCP header
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // Check destination port is 23 (Telnet)
    if (tcp->dest == bpf_htons(23)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
