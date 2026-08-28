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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, unsigned char[ETH_ALEN]);
} route_table_41 SEC(".maps");

SEC("xdp")
int xdp_route_nrf_l2_041(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Unchecked pointer dereference on map lookup
    __u32 dst_ip = ip->daddr;
    unsigned char *next_mac = bpf_map_lookup_elem(&route_table_41, &dst_ip);
    __builtin_memcpy(eth->h_dest, next_mac, ETH_ALEN);
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
