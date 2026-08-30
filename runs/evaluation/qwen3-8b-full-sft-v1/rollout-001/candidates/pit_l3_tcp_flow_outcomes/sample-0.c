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
    __u16 pad;
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
    __u32 syn_seen;
    __u32 fin_seen;
    __u32 rst_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} tcp_flow_map_3 SEC(".maps");

SEC("xdp")
int xdp_telemetry_pit_l3_tcp_flow_outcomes(struct xdp_md *ctx) {
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

    __u64 wire_len = (__u64)data_end - (__u64)data;
    __u32 syn = (tcp->syn != 0);
    __u32 fin = (tcp->fin != 0);
    __u32 rst = (tcp->rst != 0);

    struct flow_val *val = bpf_map_lookup_elem(&tcp_flow_map_3, &key);
    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, wire_len);
        __sync_fetch_and_add(&val->syn_seen, syn);
        __sync_fetch_and_add(&val->fin_seen, fin);
        __sync_fetch_and_add(&val->rst_seen, rst);
    } else {
        struct flow_val initial = {
            .packets = 1,
            .bytes = wire_len,
            .syn_seen = syn,
            .fin_seen = fin,
            .rst_seen = rst,
        };
        bpf_map_update_elem(&tcp_flow_map_3, &key, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
<|im_end|>
