#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Check source IP address against subnet 198.51.100.0/24
    u32 saddr = bpf_ntohl(ip->saddr);
    if ((saddr & 0xFFFFFF00) == 0xC6336400) {
        // Subnet match, check UDP and port 53
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(*ip));
            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
                return XDP_PASS;
            if (ntohs(udp->dest) == 53)
                return XDP_PASS;
        }
        // Subnet match but not UDP or port 53, drop
        return XDP_DROP;
    }

    // Non-matching subnet or non-IPv4 frame, pass
    return XDP_PASS;
}
