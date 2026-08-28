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
} flow_metrics_4 SEC(".maps");

SEC("xdp")
int xdp_telemetry_pit_l3_004(struct xdp_md *ctx) {
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

    struct flow_tuple key = {};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
        key.dport = udp->dest;
    } else {
        return XDP_PASS;
    }

    __u64 pkt_len = (__u64)data_end - (__u64)data;
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_metrics_4, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_len);
        stats->last_seen = bpf_ktime_get_ns();
    } else {
        struct flow_stats initial = {
            .packets = 1,
            .bytes = pkt_len,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_metrics_4, &key, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
