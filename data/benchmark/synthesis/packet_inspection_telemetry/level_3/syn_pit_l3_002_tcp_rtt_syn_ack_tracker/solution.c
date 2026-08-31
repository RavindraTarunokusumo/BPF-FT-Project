#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, __u64); // timestamp ns
    __uint(max_entries, 1024);
} syn_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0: <1ms, 1: 1-10ms, 2: 10-100ms, 3: >100ms
} rtt_histogram_map SEC(".maps");

SEC("xdp")
int xdp_tcp_rtt_tracker(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();

    if (tcp->syn && !tcp->ack) {
        struct flow_key fwd = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = tcp->source,
            .dst_port = tcp->dest,
        };
        bpf_map_update_elem(&syn_ts_map, &fwd, &now, BPF_ANY);
        return XDP_PASS;
    }

    if (tcp->syn && tcp->ack) {
        struct flow_key rev = {
            .src_ip = ip->daddr,
            .dst_ip = ip->saddr,
            .src_port = tcp->dest,
            .dst_port = tcp->source,
        };
        __u64 *syn_time = bpf_map_lookup_elem(&syn_ts_map, &rev);
        if (syn_time) {
            __u64 rtt_ns = now > *syn_time ? (now - *syn_time) : 0;
            __u32 key = 0;
            if (rtt_ns < 1000000ULL) key = 0;         // < 1ms
            else if (rtt_ns < 10000000ULL) key = 1;   // 1-10ms
            else if (rtt_ns < 100000000ULL) key = 2;  // 10-100ms
            else key = 3;                             // > 100ms

            __u64 *cnt = bpf_map_lookup_elem(&rtt_histogram_map, &key);
            if (cnt)
                *cnt += 1;
            bpf_map_delete_elem(&syn_ts_map, &rev);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
