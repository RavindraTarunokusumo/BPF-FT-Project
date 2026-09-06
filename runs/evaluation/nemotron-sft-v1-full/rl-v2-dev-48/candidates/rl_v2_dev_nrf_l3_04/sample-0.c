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

SEC("xdp")
int xdp_route_rl_v2_dev_nrf_l3_04(struct xdp_md *ctx) {
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

    __u8 *route = bpf_lpm_lookup(&dev_route_table_4, &key, sizeof(key), 0);
    if (route) {
        struct ethhdr *d = (void *)&eth;
        __builtin_memcpy(d->h_dest, route, ETH_ALEN);
    } else {
        __u8 def_mac[ETH_ALEN] = {52, 54, 0, 0, 0, 0xfe};
        struct ethhdr *d = (void *)&eth;
        __builtin_memcpy(d->h_dest, def_mac, ETH_ALEN);
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
