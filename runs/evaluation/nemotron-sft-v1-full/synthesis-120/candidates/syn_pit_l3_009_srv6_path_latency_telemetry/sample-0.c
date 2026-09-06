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
} srv6_path_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_009_srv6_path_latency_telemetry(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_IPV6)
        return XDP_PASS;

    struct ipv6hdr *ipv6 = (void *)(ip + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return XDP_PASS;

    if (ipv6->nexthdr != 43)
        return XDP_PASS;

    __u32 path_hash = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++)
        path_hash ^= ipv6->s6_addr32[i];

    struct path_metrics *metrics = bpf_map_lookup_elem(&srv6_path_map, &path_hash);
    if (metrics) {
        metrics->pkts += 1;
        metrics->bytes += ipv6->payload_len;
        metrics->hops += 4; // Assuming 4 SIDs in the active Segment List
    } else {
        struct path_metrics initial = {
            .pkts = 1,
            .bytes = ipv6->payload_len,
            .hops = 4,
            .pad = 0,
        };
        bpf_map_update_elem(&srv6_path_map, &path_hash, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
