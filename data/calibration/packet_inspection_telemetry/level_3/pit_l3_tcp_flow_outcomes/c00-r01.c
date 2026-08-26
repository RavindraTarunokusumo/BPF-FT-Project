#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u32 syn_seen;
    __u32 fin_seen;
    __u32 rst_seen;
};

struct bpf_map_def SEC("maps") tcp_flow_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct flow_value),
    .max_entries = 32768,
};

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_tcp_flow_stats(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != BPF_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + (ip->ihl * 4)) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
    if ((void *)(tcp + (tcp->doff * 4)) > data_end)
        return XDP_PASS;

    int syn = (tcp->tcp_flags & TH_SYN) != 0;
    int fin = (tcp->tcp_flags & TH_FIN) != 0;
    int rst = (tcp->tcp_flags & TH_RST) != 0;

    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    struct flow_value *val;
    val = bpf_map_lookup_elem(&tcp_flow_map, &key);
    if (!val) {
        struct flow_value init = {
            .packets = 1,
            .bytes = data_end - data,
            .syn_seen = syn,
            .fin_seen = fin,
            .rst_seen = rst,
        };
        bpf_map_update_elem(&tcp_flow_map, &key, &init, BPF_ANY);
    } else {
        val->packets += 1;
        val->bytes += data_end - data;
        val->syn_seen |= syn;
        val->fin_seen |= fin;
        val->rst_seen |= rst;
    }

    return XDP_PASS;
}
