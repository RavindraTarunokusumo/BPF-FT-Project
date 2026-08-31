#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
    __uint(max_entries, 65536);
} flow_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    struct flow_key key = {0};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    }

    struct flow_val *val = bpf_map_lookup_elem(&flow_map, &key);
    if (val) {
        // Verifier fault: variable pointer arithmetic on map value
        __u64 *p = (__u64 *)((void *)val + (key.proto == IPPROTO_TCP ? 0 : 8));
        *p += 1;
    } else {
        struct flow_val init = {.packets = 1, .bytes = (__u64)(data_end - data)};
        bpf_map_update_elem(&flow_map, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
