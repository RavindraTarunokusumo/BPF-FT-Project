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
    __uint(max_entries, 4096);
} src_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 32);
} iat_hist SEC(".maps");

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

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    __u64 *last = bpf_map_lookup_elem(&src_ts_map, &src);
    if (last && *last != 0 && now > *last) {
        __u64 delta = now - *last;
        __u32 bucket = (delta >> 20) & 31;
        __u64 *cnt = bpf_map_lookup_elem(&iat_hist, &bucket);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
    }
    bpf_map_update_elem(&src_ts_map, &src, &now, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
