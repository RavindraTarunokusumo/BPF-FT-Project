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
} tcp_flow_map_2 SEC(".maps");

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

    unsigned int ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.sport = tcp->source;
    key.dport = tcp->dest;

    struct flow_val *val = bpf_map_lookup_elem(&tcp_flow_map_2, &key);
    if (val) {
        val->packets += 1;
        val->bytes += (__u64)ctx->len;
        if (tcp->syn)
            val->syn_seen = 1;
        if (tcp->fin)
            val->fin_seen = 1;
        if (tcp->rst)
            val->rst_seen = 1;
    } else {
        struct flow_val initial = {
            .packets = 1,
            .bytes = (__u64)ctx->len,
            .syn_seen = (tcp->syn ? 1 : 0),
            .fin_seen = (tcp->fin ? 1 : 0),
            .rst_seen = (tcp->rst ? 1 : 0),
        };
        bpf_map_update_elem(&tcp_flow_map_2, &key, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
