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
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} gre_split_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l1_002_gre_protocol_split(struct xdp_md *ctx) {
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

    if (ip->protocol != 47)
        return XDP_PASS;

    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    if (__builtin_memcmp(tmp_mac, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) == 0)
        return XDP_PASS;

    struct gre_hdr *gre = (void *)(ip + 1);
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    if (ip->protocol == IPPROTO_IP)
        key = 0;
    else if (ip->protocol == IPPROTO_IPV6)
        key = 1;
    else
        key = 2;

    bpf_map_inc(&gre_split_map, &key, 1, BPF_MAP_FLAGS);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
