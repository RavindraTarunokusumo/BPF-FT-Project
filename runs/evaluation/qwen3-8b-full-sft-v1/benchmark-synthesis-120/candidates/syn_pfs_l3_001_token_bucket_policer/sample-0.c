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


struct bucket_state {
    __u64 last_time_ns;
    __u64 tokens;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct bucket_state);
} policer_map_1 SEC(".maps");

SEC("xdp")
int xdp_token_bucket_policer(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 pkt_len = (__u64)data_end - (__u64)data;
    if (pkt_len == 0)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __be32 src_ip = ip->saddr;

    struct bucket_state *bs = bpf_map_lookup_elem(&policer_map_1, &src_ip);
    if (!bs) {
        struct bucket_state initial = {
            .last_time_ns = bpf_ktime_get_ns(),
            .tokens = BURST_CAPACITY,
        };
        __u64 ns = bpf_ktime_get_ns();
        bs = bpf_map_update_elem(&policer_map_1, &src_ip, &initial, BPF_ANY);
        if (!bs)
            return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - bs->last_time_ns;
    __u64 rate_ns = 1000000000ULL / RATE_BYTES_PER_SEC;

    if (elapsed > rate_ns) {
        __u64 tokens = BURST_CAPACITY - (elapsed / rate_ns) * (RATE_BYTES_PER_SEC);
        if (tokens < BURST_CAPACITY)
            bs->tokens = tokens;
        bs->last_time_ns = now;
    }

    if (pkt_len > BURST_CAPACITY || bs->tokens < pkt_len)
        return XDP_DROP;

    bs->tokens -= pkt_len;
    bs->last_time_ns = now;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
