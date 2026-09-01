#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_v2_nrf_l1_045(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if (tcp->dest == bpf_htons(5353)) {
            unsigned char tmp_mac[ETH_ALEN];
            __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);
            return XDP_TX;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
