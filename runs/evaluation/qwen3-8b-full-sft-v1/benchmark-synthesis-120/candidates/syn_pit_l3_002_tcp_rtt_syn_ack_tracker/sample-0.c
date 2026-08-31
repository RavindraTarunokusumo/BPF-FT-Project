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
} syn_ts_map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} rtt_histogram_map_2 SEC(".maps");

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

    struct flow_key key = {};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.sport = tcp->source;
    key.dport = tcp->dest;
    key.proto = ip->protocol;

    if (tcp->syn && !tcp->ack) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_ts_map_2, &key, &ts, BPF_ANY);
        return XDP_PASS;
    }

    if (!tcp->ack || tcp->syn)
        return XDP_PASS;

    __u64 *syn_ts = bpf_map_lookup_elem(&syn_ts_map_2, &key);
    if (!syn_ts) {
        // Not a SYN-ACK response
        return XDP_PASS;
    }

    __u64 delta = bpf_ktime_get_ns() - *syn_ts;
    __u32 bucket = 3; // > 100ms

    if (delta < 1000000)
        bucket = 0;
    else if (delta < 10000000)
        bucket = 1;
    else if (delta < 100000000)
        bucket = 2;

    __u64 *cnt = bpf_map_lookup_elem(&rtt_histogram_map_2, &bucket);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    bpf_map_delete_elem(&syn_ts_map_2, &key);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
