#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define BLOOM_BITS 4096
#define BLOOM_WORDS (BLOOM_BITS / 64)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, BLOOM_WORDS);
} bloom_filter SEC(".maps");

static __always_inline __u32 hash1(__u32 val) {
    val = ((val >> 16) ^ val) * 0x45d9f3b;
    val = ((val >> 16) ^ val) * 0x45d9f3b;
    val = (val >> 16) ^ val;
    return val % BLOOM_BITS;
}

static __always_inline __u32 hash2(__u32 val) {
    val = (val ^ 0x61) ^ (val >> 16);
    val = val + (val << 3);
    val = val ^ (val >> 4);
    val = val * 0x27d4eb2d;
    val = val ^ (val >> 15);
    return val % BLOOM_BITS;
}

static __always_inline __u32 hash3(__u32 val) {
    val = (val ^ 0xDEADBEEF) * 0x85ebca6b;
    val = val ^ (val >> 13);
    val = val * 0xc2b2ae35;
    val = val ^ (val >> 16);
    return val % BLOOM_BITS;
}

SEC("xdp")
int xdp_bloom_filter_blocklist(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = bpf_ntohl(ip->saddr);

    __u32 h1 = hash1(src_ip);
    __u32 h2 = hash2(src_ip);
    __u32 h3 = hash3(src_ip);

    __u32 word1 = h1 / 64;
    __u32 bit1 = h1 % 64;
    __u32 word2 = h2 / 64;
    __u32 bit2 = h2 % 64;
    __u32 word3 = h3 / 64;
    __u32 bit3 = h3 % 64;

    __u64 *w1 = bpf_map_lookup_elem(&bloom_filter, &word1);
    if (!w1 || !(*w1 & (1ULL << bit1)))
        return XDP_PASS;

    __u64 *w2 = bpf_map_lookup_elem(&bloom_filter, &word2);
    if (!w2 || !(*w2 & (1ULL << bit2)))
        return XDP_PASS;

    __u64 *w3 = bpf_map_lookup_elem(&bloom_filter, &word3);
    if (!w3 || !(*w3 & (1ULL << bit3)))
        return XDP_PASS;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
