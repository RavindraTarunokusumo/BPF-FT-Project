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
} policy_devmap SEC(".maps");

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

    __u8 *s = (void *)&ip->saddr;
    if (s[0] != 192 || s[1] != 168 || s[2] != 10 || s[3] != 50)
        return XDP_PASS;
    
    __u8 *d = (void *)&ip->daddr;
    if (d[0] != 192 || d[1] != 168 || d[2] != 20 || d[3] != 55)
        return XDP_PASS;
    
    if (ip->protocol == IPPROTO_TCP) {
        return bpf_redirect_map(&policy_devmap, 0, 0);
    } else if (ip->protocol == IPPROTO_UDP) {
        return bpf_redirect_map(&policy_devmap, 1, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
