#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("license")
char _license[] SEC("license") = "GPL";

// Define the LPM trie map for policy rules
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
        __u8 proto;
        __u32 egress_idx;
    });
} policy_rules SEC(".maps");

// Define the DEVMAP for egress devices
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 4);
} policy_devmap SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
    struct ethhdr *eth = data;
    // Convert Ethernet protocol to host byte order and check for IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    // Check IPv4 header bounds
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }
    struct iphdr *iph = data + sizeof(struct ethhdr);
    __u32 saddr = iph->saddr;
    __u32 daddr = iph->daddr;
    __u8 protocol = iph->protocol;

    // Lookup in policy_rules with prefixlen=32 and src_ip=saddr
    struct {
        __u32 prefixlen;
        __u32 src_ip;
    } key = {32, saddr};
    struct {
        __u32 dst_prefix;
        __u8 proto;
        __u32 egress_idx;
    } *rule = bpf_map_lookup_elem(&policy_rules, &key);
    if (!rule) {
        return XDP_PASS;
    }

    // Check protocol match
    if (rule->proto != 0 && rule->proto != protocol) {
        return XDP_PASS;
    }

    // Check destination prefix match
    __u32 masked_daddr = bpf_ntohl(daddr) & rule->dst_prefix;
    if (masked_daddr != rule->dst_prefix) {
        return XDP_PASS;
    }

    // Redirect via devmap
    int ret = bpf_redirect_map(&policy_devmap, rule->egress_idx, 0);
    if (ret == 0) {
        return XDP_REDIRECT;
    }

    return XDP_PASS;
}
