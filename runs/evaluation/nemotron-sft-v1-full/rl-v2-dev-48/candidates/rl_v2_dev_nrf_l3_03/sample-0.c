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

struct route_table_entry_3 {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct route_table_entry_3);
    __type(value, struct route_table_entry_3);
    __flags(BPF_F_NO_PREALLOC);
} dev_route_table_3 SEC(".maps");

SEC("xdp")
int xdp_route_rl_v2_dev_nrf_l3_03(struct xdp_md *ctx) {
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

    struct route_table_entry_3 key = {};
    key.prefixlen = ip->daddr & 0xFF;
    // Simple LPM trie lookup for /24 subnets
    key.data = ip->daddr & bpf_htons(0xFFFFFF00);

    struct route_table_entry_3 *r = bpf_map_lookup_elem(&dev_route_table_3, &key);
    if (r) {
        struct ethhdr *d = (void *)(ip + 1);
        if ((void *)(d + 1) > data_end)
            return XDP_PASS;
        __builtin_memcpy(d->h_dest, r->data, ETH_ALEN);
    } else {
        struct ethhdr *d = (void *)(ip + 1);
        if ((void *)(d + 1) > data_end)
            return XDP_PASS;
        __builtin_memcpy(d->h_dest, "\x52\x54\x00\x00\x00\xfe", ETH_ALEN);
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
