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
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct route_key);
    __type(value, __u32);
} redirect_route_2 SEC(".maps");

struct route_key {
    __u32 prefixlen;
    __u32 data[3];
};

SEC("xdp")
int xdp_route_rl_v2_conf_nrf_l3_02(struct xdp_md *ctx) {
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

    struct route_key key = {};
    key.prefixlen = 32;
    __builtin_memcpy(key.data, &ip->daddr, sizeof(ip->daddr));

    __u32 *ifindex = bpf_lpm_trie_lookup(&redirect_route_2, &key, sizeof(key), 0);
    if (ifindex) {
        unsigned char tmp_mac[ETH_ALEN];
        __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);
        return bpf_redirect(*ifindex, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
