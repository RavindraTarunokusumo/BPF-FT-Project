#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define RATE_BYTES_PER_SEC 10000ULL
#define BURST_CAPACITY      5000ULL
#define NS_PER_SEC          1000000000ULL

struct bucket_state {
    __u64 last_time_ns;
    __u64 tokens;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct bucket_state);
    __uint(max_entries, 1024);
} policer_map SEC(".maps");

SEC("xdp")
int xdp_token_bucket_policer(struct xdp_md *ctx) {
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

    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
    if (pkt_len > BURST_CAPACITY)
        return XDP_DROP;

    __be32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct bucket_state *st = bpf_map_lookup_elem(&policer_map, &src_ip);
    if (!st) {
        struct bucket_state new_st;
        new_st.last_time_ns = now;
        new_st.tokens = BURST_CAPACITY - pkt_len;
        bpf_map_update_elem(&policer_map, &src_ip, &new_st, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = now > st->last_time_ns ? (now - st->last_time_ns) : 0;
    __u64 generated_tokens = (elapsed * RATE_BYTES_PER_SEC) / NS_PER_SEC;
    __u64 current_tokens = st->tokens + generated_tokens;
    if (current_tokens > BURST_CAPACITY)
        current_tokens = BURST_CAPACITY;

    if (current_tokens < pkt_len) {
        st->last_time_ns = now;
        st->tokens = current_tokens;
        return XDP_DROP;
    }

    st->tokens = current_tokens - pkt_len;
    st->last_time_ns = now;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
