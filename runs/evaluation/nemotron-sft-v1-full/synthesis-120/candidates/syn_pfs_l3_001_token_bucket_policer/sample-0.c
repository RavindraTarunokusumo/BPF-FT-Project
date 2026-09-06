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
} policer_map SEC(".maps");

SEC("xdp")
int xdp_syn_pfs_l3_001_token_bucket_policer(struct xdp_md *ctx) {
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

    __be32 src_ip = ip->saddr;
    struct bucket_state *state = bpf_map_lookup_elem(&policer_map, &src_ip);
    if (!state) {
        state = &policer_map[src_ip];
        // Initialize
        state->last_time_ns = bpf_ktime_get_ns();
        state->tokens = BURST_CAPACITY;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ns = now - state->last_time_ns;
    __u64 tokens_to_add = (elapsed_ns * RATE_BYTES_PER_SEC) / 1000000000000ULL;
    if (tokens_to_add > 0) {
        state->tokens += tokens_to_add;
        if (state->tokens > BURST_CAPACITY)
            state->tokens = BURST_CAPACITY;
        state->last_time_ns = now;
    }

    __u64 pkt_len = (__u64)data_end - (__u64)data;
    if (pkt_len > BURST_CAPACITY) {
        state->tokens = 0;
        return XDP_DROP;
    }

    if (state->tokens < pkt_len) {
        state->tokens = 0;
        return XDP_DROP;
    }

    state->tokens -= pkt_len;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
