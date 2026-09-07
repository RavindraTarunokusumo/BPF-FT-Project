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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} prefix_config SEC(".maps");

SEC("xdp")
int xdp_route_nrf_l2_prefix_redirect(struct xdp_md *ctx) {
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

    __u32 dst = bpf_ntohl(ip->daddr);
    
    if ((dst & 0xFF000000) == 0x0A000000) {
        __u32 ifindex = 0;
        if (bpf_map_lookup_elem(&prefix_config, &ifindex) == 0 && ifindex > 0)
            return bpf_redirect(ifindex, 0);
    } else if ((dst & 0xFFF00000) == 0xAC100000) {
        __u32 ifindex = 1;
        if (bpf_map_lookup_elem(&prefix_config, &ifindex) == 0 && ifindex > 0)
            return bpf_redirect(ifindex, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
