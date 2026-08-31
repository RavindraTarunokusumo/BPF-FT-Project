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
    __uint(max_entries, 256);
    __uint(flags, BPF_F_NO_PREALLOC);
    __type(key, struct {
        __u32 prefixlen;
        __u32 src_ip;
    });
    __type(value, struct {
        __u32 dst_prefix;
        __u8  proto;
        __u32 egress_idx;
    });
} policy_rules_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} policy_devmap_3 SEC(".maps");

SEC("xdp")
int xdp_policy_router_nrf_l3(struct xdp_md *ctx) {
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

    struct {
        __u32 prefixlen;
        __u32 src_ip;
    } key = {
        .prefixlen = 32,
        .src_ip = ip->saddr,
    };

    struct {
        __u32 dst_prefix;
        __u8  proto;
        __u32 egress_idx;
    } *val = bpf_map_lookup_elem(&policy_rules_3, &key);
    if (!val) {
        // No rule found, pass
        return XDP_PASS;
    }

    if (val->proto != 0 && val->proto != ip->protocol)
        return XDP_PASS;

    __u32 daddr = ip->daddr;
    if ((daddr & val->dst_prefix) != val->dst_prefix)
        return XDP_PASS;

    __u32 dev_idx = val->egress_idx;
    if (dev_idx >= 4)
        return XDP_PASS;

    __u32 *dev = bpf_map_lookup_elem(&policy_devmap_3, &dev_idx);
    if (!dev)
        return XDP_PASS;

    return bpf_redirect_map(&policy_devmap_3, dev_idx, 0);
}

char _license[] SEC("license") = "GPL";
