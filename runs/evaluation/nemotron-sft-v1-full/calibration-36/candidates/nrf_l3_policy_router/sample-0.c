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


struct policy_key {
    __u32 prefixlen;
    __u32 src_ip;
};

struct policy_val {
    __u32 dst_prefix;
    __u8 proto;
    __u32 egress_idx;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(flag, BPF_F_NO_PREALLOC);
    __type(key, struct policy_key);
    __type(value, struct policy_val);
} policy_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} policy_devmap SEC(".maps");

SEC("xdp")
int xdp_route_nrf_l3_policy_router(struct xdp_md *ctx) {
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

    struct policy_key key = {};
    key.prefixlen = 32;
    key.src_ip = ip->saddr;

    struct policy_val *val = bpf_map_lookup_elem(&policy_rules, &key);
    if (val) {
        if ((val->proto == 0 || val->proto == ip->protocol) &&
            ((bpf_ntohl(ip->daddr) & val->dst_prefix) == val->dst_prefix)) {
            return bpf_redirect_map(&policy_devmap, val->egress_idx, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
