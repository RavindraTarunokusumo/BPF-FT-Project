#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct session_key {
    __u32 saddr;
    __u16 sport;
    __u8 proto;
    __u8 pad;
};

struct session_val {
    __u64 last_seen;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct session_key);
    __type(value, struct session_val);
    __uint(max_entries, 16384);
} session_map SEC(".maps");

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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct session_key key = {0};
    key.saddr = ip->saddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
    } else {
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 wire_len = (__u64)(data_end - data);

    struct session_val *val = bpf_map_lookup_elem(&session_map, &key);
    if (val) {
        val->last_seen = now;
        __sync_fetch_and_add(&val->total_bytes, wire_len);
    } else {
        struct session_val init = {.last_seen = now, .total_bytes = wire_len};
        bpf_map_update_elem(&session_map, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
