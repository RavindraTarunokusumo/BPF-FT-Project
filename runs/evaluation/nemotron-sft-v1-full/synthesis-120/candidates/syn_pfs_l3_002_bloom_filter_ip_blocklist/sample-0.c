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

SEC("xdp")
int xdp_filter_syn_pfs_l3_002_bloom_filter_ip_blocklist(struct xdp_md *ctx) {
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

    __u32 hash_ip = ntohl(ip->saddr) % 4096;

    __u32 hash1 = hash_ip % 64;
    __u32 hash2 = (hash_ip * 0x9e3779b9) % 64;
    __u32 hash3 = (hash_ip * 0x85ebca6b) % 64;

    __u64 word1 = bpf_map_lookup_elem(&bloom_filter, &hash1);
    if (!word1)
        return XDP_PASS;

    __u64 word2 = bpf_map_lookup_elem(&bloom_filter, &hash2);
    if (!word2)
        return XDP_PASS;

    __u64 word3 = bpf_map_lookup_elem(&bloom_filter, &hash3);
    if (!word3)
        return XDP_PASS;

    __u64 bit1 = 1ULL << hash_ip;
    __u64 bit2 = 1ULL << (hash_ip % 64);
    __u64 bit3 = 1ULL << (hash_ip % 64);

    if ((word1 & bit1) && (word2 & bit2) && (word3 & bit3))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
