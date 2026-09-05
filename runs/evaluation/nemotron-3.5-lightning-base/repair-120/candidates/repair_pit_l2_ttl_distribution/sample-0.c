#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* 256-entry per-CPU array map keyed by __u32 TTL values */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} ttl_dist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Verify Ethernet frame bounds */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);

    /* Verify IPv4 header bounds */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Promote ip->ttl (__u8) to __u32 key and lookup/map update */
    __u32 key = ip->ttl;            /* implicit promotion __u8 -> __u32 */
    __u64 *cnt = bpf_map_lookup_elem(&ttl_dist, &key);
    if (cnt)
        (*cnt)++;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
