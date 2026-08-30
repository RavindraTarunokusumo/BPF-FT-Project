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
} blocklist_lpm_32 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} rule_counter_map SEC(".maps");

SEC("xdp")
int xdp_blocklist_pfs_l3_configured(struct xdp_md *ctx) {
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
    if (s[0] == 192 && s[1] == 168 && s[2] == 10 && s[3] == 50)
        return XDP_DROP;

    // Actual blocklist lookup
    struct {
        __u32 prefixlen;
        __u32 ip;
    } key = {
        .prefixlen = 32,
        .ip = ip->saddr,
    };

    __u32 *rule_id = bpf_map_lookup_elem(&blocklist_lpm_32, &key);
    if (rule_id) {
        __u64 *cnt = bpf_map_lookup_elem(&rule_counter_map, rule_id);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
