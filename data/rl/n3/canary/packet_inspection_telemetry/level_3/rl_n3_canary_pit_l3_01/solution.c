#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} flow_stat_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} global_traffic_map SEC(".maps");

SEC("xdp")
int xdp_dual_telemetry(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u64 *val = bpf_map_lookup_elem(&flow_stat_map, &src);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 init_c = 1;
        bpf_map_update_elem(&flow_stat_map, &src, &init_c, BPF_NOEXIST);
    }

    __u32 g_key = 0;
    __u64 *g_cnt = bpf_map_lookup_elem(&global_traffic_map, &g_key);
    if (g_cnt)
        __sync_fetch_and_add(g_cnt, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
