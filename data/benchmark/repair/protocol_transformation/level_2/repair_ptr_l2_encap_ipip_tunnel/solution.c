#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;

    if (bpf_xdp_adjust_head(ctx, -20))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    *new_eth = eth_saved;

    struct iphdr *outer_ip = (void *)(new_eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_DROP;

    outer_ip->version = 4;
    outer_ip->ihl = 5;
    outer_ip->tos = 0;
    outer_ip->tot_len = bpf_htons((__u16)((long)data_end - (long)outer_ip));
    outer_ip->id = 0;
    outer_ip->frag_off = 0;
    outer_ip->ttl = 64;
    outer_ip->protocol = 4; // IPPROTO_IPIP
    outer_ip->saddr = bpf_htonl(0xC0A80101); // 192.168.1.1
    outer_ip->daddr = bpf_htonl(0xC0A80102); // 192.168.1.2
    outer_ip->check = 0;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
