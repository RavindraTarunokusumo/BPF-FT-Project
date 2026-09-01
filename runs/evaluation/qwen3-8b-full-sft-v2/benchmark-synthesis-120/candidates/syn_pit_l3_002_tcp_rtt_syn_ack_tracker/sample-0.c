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

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, __u64);
} syn_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} rtt_histogram_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_002_tcp_rtt_syn_ack_tracker(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn && !tcp->ack) {
        struct flow_key key = {};
        key.saddr = ip->saddr;
        key.daddr = ip->daddr;
        key.sport = tcp->source;
        key.dport = tcp->dest;
        key.proto = ip->protocol;

        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_ts_map, &key, &now, BPF_ANY);
        return XDP_PASS;
    }

    if (tcp->ack && !tcp->syn) {
        struct flow_key key = {};
        key.saddr = ip->daddr;
        key.daddr = ip->saddr;
        key.sport = tcp->dest;
        key.dport = tcp->source;
        key.proto = ip->protocol;

        __u64 *syn_time = bpf_map_lookup_elem(&syn_ts_map, &key);
        if (!syn_time)
            return XDP_PASS;

        __u64 now = bpf_ktime_get_ns();
        __u64 delta = now - *syn_time;

        __u32 slot = 0;
        if (delta > 1000000)
            slot = 1;
        if (delta > 100000000)
            slot = 2;
        if (delta > 1000000000)
            slot = 3;

        __u64 *cnt = bpf_map_lookup_elem(&rtt_histogram_map, &slot);
        if (cnt)
            *cnt += delta;

        bpf_map_delete_elem(&syn_ts_map, &key);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
