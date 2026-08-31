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


struct path_metrics {
    __u64 pkts;
    __u64 bytes;
    __u32 hops;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct path_metrics);
} srv6_path_map_9 SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_009_srv6_path_latency(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    if (ip6->protocol != 43)
        return XDP_PASS;

    struct ipv6_sr_hdr *srh = (void *)(ip6 + 1);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;

    __u32 path_hash = 0;
    #pragma unroll
    for (int i = 0; i < srh->segments_left; i++) {
        void *sid = (void *)(srh + 1) + i * sizeof(__u128);
        if ((void *)sid > data_end)
            return XDP_PASS;
        __u128 *sid_val = sid;
        __u64 *p = (__u64 *)sid_val;
        path_hash ^= (p[0] ^ p[1]);
    }

    __u64 pkt_len = (__u64)data_end - (__u64)data;
    struct path_metrics *cnt = bpf_map_lookup_elem(&srv6_path_map_9, &path_hash);
    if (cnt) {
        __sync_fetch_and_add(&cnt->pkts, 1);
        __sync_fetch_and_add(&cnt->bytes, pkt_len);
        __sync_fetch_and_add(&cnt->hops, srh->segments_left + 1);
    } else {
        struct path_metrics initial = {
            .pkts = 1,
            .bytes = pkt_len,
            .hops = srh->segments_left + 1,
        };
        bpf_map_update_elem(&srv6_path_map_9, &path_hash, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
