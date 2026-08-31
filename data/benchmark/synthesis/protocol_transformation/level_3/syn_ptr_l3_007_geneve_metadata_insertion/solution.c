#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct genevehdr {
    __u8 opt_len:6;
    __u8 ver:2;
    __u8 rsvd1:6;
    __u8 critical:1;
    __u8 oam:1;
    __be16 proto_type;
    __u8 vni[3];
    __u8 reserved2;
};

struct geneve_opt {
    __be16 opt_class;
    __u8 type;
    __u8 flags_length;
    __u32 data;
};

SEC("xdp")
int xdp_geneve_meta_insert(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    struct genevehdr *gen = (void *)(udp + 1);
    if ((void *)(gen + 1) > data_end)
        return XDP_PASS;

    if (gen->opt_len != 0)
        return XDP_PASS;

    // Expand headroom by 8 bytes
    if (bpf_xdp_adjust_head(ctx, -8))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    new_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *new_ip = (void *)(new_eth + 1);
    if ((void *)(new_ip + 1) > data_end)
        return XDP_PASS;

    struct udphdr *new_udp = (void *)(new_ip + 1);
    if ((void *)(new_udp + 1) > data_end)
        return XDP_PASS;

    struct genevehdr *new_gen = (void *)(new_udp + 1);
    if ((void *)(new_gen + 1) > data_end)
        return XDP_PASS;

    new_gen->opt_len = 2; // 2 words = 8 bytes

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
