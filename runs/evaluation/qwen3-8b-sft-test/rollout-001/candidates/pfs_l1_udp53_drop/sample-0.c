#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/byteorder/generic.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int pfs_l1_udp53_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Check Ethernet protocol is IPv4 (ETH_P_IP = 0x0800)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IPv4 header
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Check IP protocol is UDP (IPPROTO_UDP = 17)
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Check IHL (Header Length) is valid
    u32 ihl = ip->ihl;
    if (ihl < 5 || ihl > 15)
        return XDP_PASS;

    // Calculate offset to UDP header
    u32 ip_header_len = ihl * 4;
    if ((void *)ip + ip_header_len > data_end)
        return XDP_PASS;

    // UDP header
    struct udphdr *udp = (void *)ip + ip_header_len;
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    // Check destination port is 53 (DNS)
    if (udp->dest == bpf_htons(53)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
