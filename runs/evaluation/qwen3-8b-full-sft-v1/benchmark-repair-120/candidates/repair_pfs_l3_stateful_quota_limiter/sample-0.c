#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10240);
} quota_map SEC(".maps");

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

    __u32 src = ip->saddr;
    __u64 *val = bpf_map_lookup_elem(&quota_map, &src);
    if (!val) {
        __u64 init_val = 1;
        bpf_map_update_elem(&quota_map, &src, &init_val, BPF_ANY);
        return XDP_PASS;
    }

    if (*val < 5) {
        __u64 new_val = (*val) + 1;
        __sync_fetch_and_add(val, 1);
        return XDP_PASS;
    }

    __sync_fetch_and_add(val, 1);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
