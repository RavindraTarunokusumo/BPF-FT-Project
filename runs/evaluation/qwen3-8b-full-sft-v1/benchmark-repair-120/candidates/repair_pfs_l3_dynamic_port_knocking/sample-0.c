#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct knock_state {
    __u8 stage;
    __u8 pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct knock_state);
    __uint(max_entries, 1024);
} knock_map SEC(".maps");

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
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u16 dport = bpf_ntohs(tcp->dest);
    struct knock_state *st = bpf_map_lookup_elem(&knock_map, &src);

    if (dport == 1111) {
        struct knock_state new_st = { .stage = 1 };
        bpf_map_update_elem(&knock_map, &src, &new_st, BPF_ANY);
        return XDP_PASS;
    } else if (dport == 2222) {
        if (st && st->stage == 1) {
            struct knock_state new_st = { .stage = 2 };
            bpf_map_update_elem(&knock_map, &src, &new_st, BPF_ANY);
        }
        return XDP_PASS;
    } else if (dport == 22) {
        if (st && st->stage == 2)
            return XDP_PASS;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
