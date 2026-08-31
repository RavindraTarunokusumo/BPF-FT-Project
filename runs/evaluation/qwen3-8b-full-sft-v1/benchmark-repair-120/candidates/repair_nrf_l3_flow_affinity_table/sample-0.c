#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} affinity_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
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
    
    __u32 src = ip->saddr;
    __u32 dst = ip->daddr;
    __u16 proto = ip->protocol;
    
    #pragma unroll
    for (__u32 i = 0; i < 4; i++) {
        __u32 key = 0;
        if (i == 0) {
            if (ip->saddr == 192 && ip->daddr == 168 && ip->protocol == 6)
                key = 1;
        } else if (i == 1) {
            if (ip->saddr == 10 && ip->daddr == 50 && ip->protocol == 17)
                key = 1;
        } else if (i == 2) {
            if (ip->saddr == 172 && ip->daddr == 20 && ip->protocol == 1)
                key = 1;
        } else if (i == 3) {
            if (ip->saddr == 192 && ip->daddr == 168 && ip->protocol == 17)
                key = 1;
        }
        if (key) {
            __u32 dev = bpf_map_lookup_elem(&affinity_devmap, &i);
            if (dev)
                return bpf_redirect(dev, 0);
        }
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
