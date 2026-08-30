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

    struct iphdr *ip_hdr = (void *)(eth + 1);
    if ((void *)(ip_hdr + 1) > data_end)
        return XDP_PASS;

    if (ip_hdr->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip_hdr->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip_hdr + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp_hdr = (void *)ip_hdr + ip_hdr_len;
    if ((void *)(tcp_hdr + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    key.saddr = ip_hdr->saddr;
    key.daddr = ip_hdr->daddr;
    key.sport = tcp_hdr->source;
    key.dport = tcp_hdr->dest;

    __u64 wire_len = (__u64)data_end - (__u64)data;
    __u64 bytes = wire_len;

    struct flow_val *val = bpf_map_lookup_elem(&tcp_flow_map_3, &key);
    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, bytes);
        if (tcp_hdr->syn)
            __sync_fetch_and_add(&val->syn_seen, 1);
        if (tcp_hdr->fin)
            __sync_fetch_and_add(&val->fin_seen, 1);
        if (tcp_hdr->rst)
            __sync_fetch_and_add(&val->rst_seen, 1);
    } else {
        struct flow_val initial = {
            .packets = 1,
            .bytes = bytes,
            .syn_seen = tcp_hdr->syn ? 1 : 0,
            .fin_seen = tcp_hdr->fin ? 1 : 0,
            .rst_seen = tcp_hdr->rst ? 1 : 0,
        };
        bpf_map_update_elem(&tcp_flow_map_3, &key, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
