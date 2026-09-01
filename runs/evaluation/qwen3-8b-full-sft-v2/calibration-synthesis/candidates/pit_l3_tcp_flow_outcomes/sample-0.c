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
    __u16 pad[2];
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
    __u32 syn_seen;
    __u32 fin_seen;
    __u32 rst_seen;
};

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
    if (wire_len > 65535)
        wire_len = 65535;

    struct flow_val *val = bpf_map_lookup_elem(&tcp_flow_map, &key);
    if (!val) {
        val = bpf_map_lookup_elem(&tcp_flow_map, &key);
        if (!val) {
            val = bpf_map_get_elem(&tcp_flow_map, &key);
            if (!val)
                return XDP_PASS;
            *val = (struct flow_val){0, 0, 0, 0, 0};
        }
    }

    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, wire_len);

    if (tcp->syn)
        __sync_fetch_and_add(&val->syn_seen, 1);
    if (tcp->fin)
        __sync_fetch_and_add(&val->fin_seen, 1);
    if (tcp->rst)
        __sync_fetch_and_add(&val->rst_seen, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
