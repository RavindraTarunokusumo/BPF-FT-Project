#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds and protocol
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header bounds
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Extract source IP and check subnet match
    __u32 saddr = bpf_ntohl(ip->saddr);
    if ((saddr & 0xFFFFFF00) == 0xC6336400) {
        // Check if UDP traffic destined for port 53
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(*ip));
            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
                return XDP_PASS;
            if (bpf_ntohs(udp->dest) == 53)
                return XDP_PASS;
        }
        // Drop matching subnet but not UDP port 53
        return XDP_DROP;
    }

    // Pass all other traffic
    return XDP_PASS;
}
