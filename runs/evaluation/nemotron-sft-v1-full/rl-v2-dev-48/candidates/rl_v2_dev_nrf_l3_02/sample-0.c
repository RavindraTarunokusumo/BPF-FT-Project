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


struct route_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct route_lpm_key);
    __type(value, unsigned char[ETH_ALEN]);
} dev_route_table_2 SEC(".maps");

SEC("xdp")
int xdp_route_rl_v2_dev_nrf_l3_02(struct xdp_md *ctx) {
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

    struct route_lpm_key key = {};
    key.prefixlen = 32;
    key.data = ip->daddr;

    unsigned char *gw_mac = bpf_map_lookup_elem(&dev_route_table_2, &key);
    if (gw_mac) {
        __builtin_memcpy(eth->h_dest, gw_mac, ETH_ALEN);
        return XDP_TX;
    }

    unsigned char default_gw_mac[ETH_ALEN] = {52, 54, 0, 0, 0, fe};
    __builtin_memcpy(eth->h_dest, default_gw_mac, ETH_ALEN);
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
