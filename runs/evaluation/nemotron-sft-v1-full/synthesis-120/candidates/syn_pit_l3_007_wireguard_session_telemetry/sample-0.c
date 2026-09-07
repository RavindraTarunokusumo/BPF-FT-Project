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

struct wg_session_stat {
    __u64 last_seen_ns;
    __u64 total_packets;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct wg_session_stat);
} wg_session_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_007_wireguard_session_telemetry(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 receiver_idx = ip->daddr.s_addr % 1024;

    struct wg_session_stat *stat = bpf_map_lookup_elem(&wg_session_map, &receiver_idx);
    if (stat) {
        stat->last_seen_ns = bpf_ktime_get_ns();
        stat->total_packets += 1;
        stat->total_bytes += ip->len;
    } else {
        struct wg_session_stat initial = {
            .last_seen_ns = bpf_ktime_get_ns(),
            .total_packets = 1,
            .total_bytes = ip->len,
        };
        bpf_map_update_elem(&wg_session_map, &receiver_idx, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
