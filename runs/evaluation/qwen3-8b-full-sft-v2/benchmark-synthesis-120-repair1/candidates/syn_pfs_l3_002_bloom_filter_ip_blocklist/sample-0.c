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
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} bloom_filter SEC(".maps");

static __u64 hash1(__u32 x) {
    return (x * 1111111111) % 4096;
}

static __u64 hash2(__u32 x) {
    return (x * 1111111113) % 4096;
}

static __u64 hash3(__u32 x) {
    return (x * 1111111117) % 4096;
}

SEC("xdp")
int xdp_bloom_filter_syn_pfs_l3_002(struct xdp_md *ctx) {
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

    __u32 saddr = ip->saddr;
    __u64 h1 = hash1(saddr);
    __u64 h2 = hash2(saddr);
    __u64 h3 = hash3(saddr);

    __u32 idx1 = h1 % 64;
    __u32 idx2 = h2 % 64;
    __u32 idx3 = h3 % 64;

    __u64 *bit1 = bpf_map_lookup_elem(&bloom_filter, &idx1);
    if (!bit1) return XDP_PASS;

    __u64 *bit2 = bpf_map_lookup_elem(&bloom_filter, &idx2);
    if (!bit2) return XDP_PASS;

    __u64 *bit3 = bpf_map_lookup_elem(&bloom_filter, &idx3);
    if (!bit3) return XDP_PASS;

    if ((*bit1 & (1ULL << (h1 % 64))) &&
        (*bit2 & (1ULL << (h2 % 64))) &&
        (*bit3 & (1ULL << (h3 % 64))))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";