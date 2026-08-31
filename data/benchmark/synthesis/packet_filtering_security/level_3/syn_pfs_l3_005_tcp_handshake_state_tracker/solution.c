#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

enum tcp_conntrack_state {
    TCP_CT_NONE = 0,
    TCP_CT_SYN_SENT = 1,
    TCP_CT_ESTABLISHED = 2,
    TCP_CT_CLOSED = 3,
};

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, __u32); // enum tcp_conntrack_state
    __uint(max_entries, 2048);
} ct_map SEC(".maps");

SEC("xdp")
int xdp_tcp_conntrack(struct xdp_md *ctx) {
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

    struct flow_key fwd = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };
    struct flow_key rev = {
        .src_ip = ip->daddr,
        .dst_ip = ip->saddr,
        .src_port = tcp->dest,
        .dst_port = tcp->source,
    };

    if (tcp->syn && !tcp->ack) {
        __u32 state = TCP_CT_SYN_SENT;
        bpf_map_update_elem(&ct_map, &fwd, &state, BPF_ANY);
        return XDP_PASS;
    }

    if (tcp->syn && tcp->ack) {
        __u32 *rev_state = bpf_map_lookup_elem(&ct_map, &rev);
        if (rev_state && *rev_state == TCP_CT_SYN_SENT) {
            __u32 state = TCP_CT_ESTABLISHED;
            bpf_map_update_elem(&ct_map, &fwd, &state, BPF_ANY);
            bpf_map_update_elem(&ct_map, &rev, &state, BPF_ANY);
            return XDP_PASS;
        }
    }

    __u32 *cur_state = bpf_map_lookup_elem(&ct_map, &fwd);
    if (!cur_state || *cur_state == TCP_CT_NONE)
        return XDP_DROP; // Drop unsolicited TCP traffic without handshake

    if (tcp->rst || tcp->fin) {
        __u32 state = TCP_CT_CLOSED;
        bpf_map_update_elem(&ct_map, &fwd, &state, BPF_ANY);
        bpf_map_update_elem(&ct_map, &rev, &state, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
