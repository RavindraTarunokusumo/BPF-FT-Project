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
    __type(key, struct {
        __u32 prefixlen;
        __u32 ip;
    });
    __type(value, __u32);
} blocklist_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} rule_counter_map SEC(".maps");

SEC("xdp")
int xdp_filter_pfs_l3_configured_blocklist(struct xdp_md *ctx) {
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

    __u32 src_ip = ip->saddr;

    struct {
        __u32 prefixlen;
        __u32 ip;
    } key = {
        .prefixlen = 32,
        .ip = src_ip
    };

    __u32 *rule_id_ptr = bpf_map_lookup_elem(&blocklist_lpm_map, &key);
    if (!rule_id_ptr)
        return XDP_PASS;

    __u32 rule_id = *rule_id_ptr;
    if (rule_id >= 64)
        return XDP_PASS;

    __u64 *cnt = bpf_map_lookup_elem(&rule_counter_map, &rule_id);
    if (cnt)
        *cnt += 1;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
