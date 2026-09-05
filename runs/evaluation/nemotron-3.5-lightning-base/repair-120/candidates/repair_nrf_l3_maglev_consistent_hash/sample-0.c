#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Maglev lookup table entry: stores the selected devmap index */
struct maglev_entry {
    __u32 dev_idx;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct maglev_entry);
    __uint(max_entries, 257);
} maglev_lut SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} maglev_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
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

    /* 5‑tuple hash modulo the 257‑slot LUT */
    __u32 hash = (ip->saddr ^ ip->daddr ^ tcp->source ^ tcp->dest) % 257;
    struct maglev_entry *entry = bpf_map_lookup_elem(&maglev_lut, &hash);
    if (entry) {
        __u32 b_idx = entry->dev_idx & 1;   /* pick one of the two devmap targets */
        return bpf_redirect_map(&maglev_devmap, b_idx, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
