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
} bloom_filter_2 SEC(".maps");

static __always_inline __u32 hash1(__u32 x) {
    x = (x ^ (x >> 16)) * 0x811C9DC5;
    x = (x ^ (x >> 16)) * 0x811C9DC5;
    x = x ^ (x >> 16);
    return x;
}

static __always_inline __u32 hash2(__u32 x) {
    x = (x ^ (x >> 15)) * 0x71589857;
    x = (x ^ (x >> 15)) * 0x71589857;
    x = x ^ (x >> 15);
    return x;
}

static __always_inline __u32 hash3(__u32 x) {
    x = (x ^ (x >> 12)) * 0x1B56C4EF;
    x = (x ^ (x >> 12)) * 0x1B56C4EF;
    x = x ^ (x >> 12);
    return x;
}

SEC("xdp")
int xdp_bloom_filter_pfs_l3_002(struct xdp_md *ctx) {
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
    if (saddr == 0)
        return XDP_PASS;

    __u32 h1 = hash1(saddr) & 4095;
    __u32 h2 = hash2(saddr) & 4095;
    __u32 h3 = hash3(saddr) & 4095;

    __u32 *bits = (void *)&bloom_filter_2;
    if ((void *)(bits + 1) > data_end)
        return XDP_PASS;

    __u64 w1 = bits[h1];
    __u64 w2 = bits[h2];
    __u64 w3 = bits[h3];

    if ((w1 & 0x01) && (w2 & 0x01) && (w3 & 0x01))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
