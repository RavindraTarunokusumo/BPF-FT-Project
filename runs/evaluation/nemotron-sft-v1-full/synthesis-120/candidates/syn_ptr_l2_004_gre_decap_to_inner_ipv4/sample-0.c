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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_transform_syn_ptr_l2_004_gre_decap_to_inner_ipv4(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (outer_ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    if (outer_ip->ihl != 5)
        return XDP_PASS;

    struct grehdr *gre = (void *)(outer_ip + 1);
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    if (gre->flags != 0)
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)(gre + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    __u8 *d = inner_eth->h_dest;
    __u8 *s = inner_eth->h_source;
    __u16 proto = inner_eth->h_proto;

    inner_eth->h_dest = eth->h_dest;
    inner_eth->h_source = eth->h_source;
    inner_eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
