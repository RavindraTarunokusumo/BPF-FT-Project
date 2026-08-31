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

struct seq_tracker {
    __u32 expected_seq;
    __u32 in_order_pkts;
    __u32 out_of_order_pkts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, struct seq_tracker);
} seq_tracker_map_6 SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_006(struct xdp_md *ctx) {
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

    __u32 payload_len = (void *)(tcp + 1) - (void *)tcp;
    if (payload_len < sizeof(struct tcphdr))
        return XDP_PASS;

    __u32 seq = tcp->seq;
    __u32 ack = tcp->ack_seq;

    struct seq_tracker *t = bpf_map_lookup_elem(&seq_tracker_map_6, &key);
    if (t) {
        if (seq == t->expected_seq) {
            t->in_order_pkts++;
            t->expected_seq += payload_len;
        } else {
            t->out_of_order_pkts++;
        }
    } else {
        __u32 initial_seq = seq;
        __u32 initial_expected = seq + payload_len;
        struct seq_tracker initial = {
            .expected_seq = initial_expected,
            .in_order_pkts = 1,
            .out_of_order_pkts = 0,
        };
        bpf_map_update_elem(&seq_tracker_map_6, &key, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
