#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32); // Rule ID
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} rule_stats SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    // Verifier error: 600-byte stack array exceeds 512 byte limit
    char audit_buffer[600];
    audit_buffer[0] = 0;

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

    struct lpm_key key = {
        .prefixlen = 32,
        .addr = ip->saddr,
    };

    __u32 *rule_id = bpf_map_lookup_elem(&lpm_blocklist, &key);
    if (rule_id) {
        __u32 rid = *rule_id;
        __u64 *cnt = bpf_map_lookup_elem(&rule_stats, &rid);
        if (cnt)
            *cnt += 1;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
