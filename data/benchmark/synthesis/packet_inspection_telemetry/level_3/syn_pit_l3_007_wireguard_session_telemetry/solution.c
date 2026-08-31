#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct wg_session_stat {
    __u64 last_seen_ns;
    __u64 total_packets;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Receiver Index
    __type(value, struct wg_session_stat);
    __uint(max_entries, 1024);
} wg_session_map SEC(".maps");

SEC("xdp")
int xdp_wg_session_telemetry(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(51820) && udp->source != bpf_htons(51820))
        return XDP_PASS;

    __u8 *wg = (void *)(udp + 1);
    if (wg + 8 > data_end)
        return XDP_PASS;

    __u32 msg_type = *(__u32 *)wg;
    if ((msg_type & 0xFF) != 4) // Type 4: Data packet
        return XDP_PASS;

    __u32 receiver_idx = *(__u32 *)(wg + 4);
    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);

    struct wg_session_stat *st = bpf_map_lookup_elem(&wg_session_map, &receiver_idx);
    if (!st) {
        struct wg_session_stat new_st = {
            .last_seen_ns = now,
            .total_packets = 1,
            .total_bytes = pkt_len,
        };
        bpf_map_update_elem(&wg_session_map, &receiver_idx, &new_st, BPF_ANY);
    } else {
        st->last_seen_ns = now;
        st->total_packets += 1;
        st->total_bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
