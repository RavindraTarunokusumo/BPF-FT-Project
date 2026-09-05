#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct tcp_flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcp_flow_key);
    __type(value, __u32);
    __uint(max_entries, 16384);
} tcp_fsm_map SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct tcp_flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    __u32 state = 0; /* default: SYN_SENT / initial */

    /* 1. SYN takes precedence – opens a new connection */
    if (tcp->syn)
        state = 0; /* STATE_SYN_SENT */

    /* 2. ACK transitions an established connection */
    if (tcp->ack && !tcp->syn)
        state = 1; /* STATE_ESTABLISHED */

    /* 3. FIN closes the connection – must be checked after ACK
     *    so that a FIN+ACK packet lands in CLOSED, not ESTABLISHED. */
    if (tcp->fin)
        state = 2; /* STATE_CLOSED */

    bpf_map_update_elem(&tcp_fsm_map, &key, &state, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
