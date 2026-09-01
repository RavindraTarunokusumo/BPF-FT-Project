#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;
    if (bpf_xdp_adjust_head(ctx, -50))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    *new_eth = eth_saved;

    new_eth->h_proto = bpf_htons(ETH_P_IP);
    struct iphdr *ip = (void *)(new_eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    *ip = (struct iphdr){
        .ihl: 5,
        .protocol: IPPROTO_UDP,
        .tot_len: bpf_htons(60 + 50),
        .saddr: bpf_htons(192),
        .daddr: bpf_htons(193),
    };

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    *udp = (struct udphdr){
        .dest: bpf_htons(6081),
        .len: bpf_htons(60 + 50),
    };

    unsigned char *geneve = (void *)(udp + 1);
    if ((void *)(geneve + 50) > data_end)
        return XDP_DROP;

    *geneve++ = GENEVE_Option::OPT_TYPE_TNV;
    *geneve++ = 8;
    *geneve++ = 0x01;
    *geneve++ = 0x02;
    *geneve++ = 0x03;
    *geneve++ = 0x04;
    *geneve++ = 0x05;
    *geneve++ = 0x06;
    *geneve++ = 0x07;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
