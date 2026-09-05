#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

struct syn_key {
    __u32 saddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct syn_key);
    __type(value, __u64);
    __uint(max_entries, 16384);
} syn_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} rtt_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct syn_key key = {
        .saddr = ip->saddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    if (tcp->syn && !tcp->ack) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_ts_map, &key, &now, BPF_ANY);
    } else if (tcp->ack && !tcp->syn) {
        __u64 *ts = bpf_map_lookup_elem(&syn_ts_map, &key);
        if (ts) {
            __u64 now = bpf_ktime_get_ns();
            __u64 rtt_us = (now > *ts) ? ((now - *ts) / 1000) : 0;
            __u32 bucket = (rtt_us < 64) ? (__u32)rtt_us : 63;
            __u64 *cnt = bpf_map_lookup_elem(&rtt_hist, &bucket);
            if (cnt)
                *cnt += 1;
            bpf_map_delete_elem(&syn_ts_map, &key);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
