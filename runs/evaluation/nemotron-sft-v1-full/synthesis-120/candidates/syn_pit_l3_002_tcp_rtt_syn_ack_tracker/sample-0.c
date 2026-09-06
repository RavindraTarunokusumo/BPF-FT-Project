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
int xdp_track_syn_pit_l3_002_tcp_rtt_syn_ack_tracker(struct xdp_md *ctx) {
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

    struct flow_key key = {};
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
        if (tcp->syn && !tcp->ack) {
            __u64 now = bpf_ktime_get_ns();
            bpf_map_update_elem(&syn_ts_map, &key, &now, BPF_ANY);
        } else {
            __u64 *syn_ts = bpf_map_lookup_elem(&syn_ts_map, &key);
            if (syn_ts) {
                __u64 rtt = now - *syn_ts;
                __u32 bucket = 0;
                if (rtt < 1000000)
                    bucket = 0;
                else if (rtt < 10000000)
                    bucket = 1;
                else if (rtt < 100000000)
                    bucket = 2;
                else
                    bucket = 3;
                __u64 *cnt = bpf_map_lookup_elem(&rtt_histogram_map, &bucket);
                if (cnt)
                    *cnt += 1;
                bpf_map_delete_elem(&syn_ts_map, &key);
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
