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

struct seq_tracker {
    __u32 expected_seq;
    __u32 in_order_pkts;
    __u32 out_of_order_pkts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct seq_tracker);
    __uint(max_entries, 1024);
} seq_tracker_map SEC(".maps");

SEC("xdp")
int xdp_tcp_ooo_detector(struct xdp_md *ctx) {
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

    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    __u32 payload_len = (__u32)((void *)data_end - ((void *)tcp + tcp_hdr_len));
    if (payload_len == 0)
        return XDP_PASS; // Only track segments with payload

    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    __u32 seq = bpf_ntohl(tcp->seq);
    struct seq_tracker *st = bpf_map_lookup_elem(&seq_tracker_map, &key);
    if (!st) {
        struct seq_tracker new_st = {
            .expected_seq = seq + payload_len,
            .in_order_pkts = 1,
            .out_of_order_pkts = 0,
        };
        bpf_map_update_elem(&seq_tracker_map, &key, &new_st, BPF_ANY);
        return XDP_PASS;
    }

    if (seq == st->expected_seq) {
        st->in_order_pkts += 1;
        st->expected_seq = seq + payload_len;
    } else {
        st->out_of_order_pkts += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
