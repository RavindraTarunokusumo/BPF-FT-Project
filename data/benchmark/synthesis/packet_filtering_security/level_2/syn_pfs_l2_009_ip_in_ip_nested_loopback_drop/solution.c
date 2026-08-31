#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_ipinip_loopback_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (outer_ip->protocol != 4) // IPPROTO_IPIP (IPv4-in-IPv4)
        return XDP_PASS;

    int outer_len = outer_ip->ihl * 4;
    if (outer_len < sizeof(struct iphdr) || (void *)outer_ip + outer_len > data_end)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)outer_ip + outer_len;
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    // Check if inner destination IP is in 127.0.0.0/8 (0x7F000000 / 0xFF000000)
    __u32 inner_dst = bpf_ntohl(inner_ip->daddr);
    if ((inner_dst & 0xFF000000) == 0x7F000000)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
