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
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_tuple);
    __type(value, struct flow_stats);
} flow_metrics_29 SEC(".maps");

SEC("xdp")
int xdp_telemetry_pit_l3_029(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // FAULT: Missing IP header check and missing struct alignment
    struct iphdr *ip = (void *)(eth + 1);
    struct flow_tuple key;
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    struct flow_stats *stats = bpf_map_lookup_elem(&flow_metrics_29, &key);
    stats->packets += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
