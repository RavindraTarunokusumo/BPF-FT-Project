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

struct flow_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} cms_sketch_map SEC(".maps");

static __always_inline __u32 hash1(__u8 *data, __u32 len) {
    __u32 h = 0;
    while (len--) {
        h = (h * 31) + *data++;
    }
    return h;
}

static __always_inline __u32 hash2(__u8 *data, __u32 len) {
    __u32 h = 0;
    while (len--) {
        h = (h * 31) + (bpf_htons(*data++) ^ 0x9E3779B9);
    }
    return h;
}

static __always_inline __u32 hash3(__u8 *data, __u32 len) {
    __u32 h = 0;
    while (len--) {
        h = (h ^ (h >> 16)) ^ (bpf_htons(*data++) ^ 0x9E3779B9);
    }
    return h;
}

static __always_inline __u32 hash4(__u8 *data, __u32 len) {
    __u32 h = 0;
    while (len--) {
        h = (h * 31) + (bpf_htons(*data++) ^ 0x9E3779B9);
    }
    return h;
}

SEC("xdp")
int xdp_telemetry_syn_pit_l3_001_count_min_sketch_heavy_hitters(struct xdp_md *ctx) {
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

    __u32 key = (ip->saddr % 1024);
    __u64 *cnt = bpf_map_lookup_elem(&cms_sketch_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
