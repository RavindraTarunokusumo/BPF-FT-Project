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


SEC("xdp")
int xdp_route_nrf_l3_flow_load_balancer(struct xdp_md *ctx) {
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

    __u32 hash = (ip->saddr ^ ip->daddr ^ (ip->sport << 16 | ip->dport) ^ ip->protocol) & 1;

    unsigned char *mac = bpf_map_lookup_elem(&backend_macs, &hash);
    if (mac) {
        __builtin_memcpy(eth->h_dest, mac, ETH_ALEN);
        return bpf_redirect_map(&backend_devmap, hash, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
