#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct lifecycle_record {
    __u64 start_ts;
    __u64 last_ts;
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct lifecycle_record);
    __uint(max_entries, 16384);
} flow_lifecycle SEC(".maps");

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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr) || (void *)ip + ip_hlen > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
        key.dport = udp->dest;
    }

    struct lifecycle_record *val = bpf_map_lookup_elem(&flow_lifecycle, &key);
    if (val) {
        val->last_ts = bpf_ktime_get_ns();
        val->packets += 1;
        val->bytes += (__u64)(data_end - data);
    } else {
        struct lifecycle_record init = {};
        init.start_ts = bpf_ktime_get_ns();
        init.last_ts = init.start_ts;
        init.packets = 1;
        init.bytes = (__u64)(data_end - data);
        bpf_map_update_elem(&flow_lifecycle, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
