#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* --- Configuration Constants --- */
#define RATE_BYTES_PER_SEC 10000ULL
#define BURST_CAPACITY     5000ULL
#define MAX_ENTRIES        1024

/* --- Per-Bucket State --- */
struct bucket_state {
    __u64 last_time_ns; /* Last token replenishment timestamp */
    __u64 tokens;       /* Current available tokens (bytes) */
};

/* --- Hash Map Declaration --- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __be32);
    __type(value, struct bucket_state);
} policer_map SEC(".maps");

/* --- XDP Entry Point --- */
SEC("xdp")
int xdp_token_policer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- Non-IPv4 Passthrough --- */
    struct eth_hdr {
        __u8 h_dest[6];
        __u8 h_source[6];
        __be16 h_proto;
    };
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct ipv4_hdr {
        __u8 ihl_version;
        __u8 tos;
        __be16 tot_len;
        __be16 id;
        __be16 frag_off;
        __u8 ttl;
        __u8 protocol;
        __be16 check;
        __be32 saddr;
        __be32 daddr;
    };
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* --- Source IP Lookup --- */
    __be32 src_ip = ip->saddr;
    struct bucket_state *state;
    state = bpf_map_lookup_elem(&policer_map, &src_ip);
    if (!state) {
        /* First packet from this source: initialise state */
        state = bpf_map_lookup_elem(&policer_map, &src_ip);
        if (!state) {
            struct bucket_state init = {
                .last_time_ns = bpf_ktime_get_ns(),
                .tokens       = BURST_CAPACITY,
            };
            bpf_map_update_elem(&policer_map, &src_ip, &init, BPF_ANY);
            state = bpf_map_lookup_elem(&policer_map, &src_ip);
            if (!state)
                return XDP_PASS; /* map update failed, allow */
        }
    }

    /* --- Token Replenishment --- */
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ns = now - state->last_time_ns;
    state->last_time_ns = now;

    /* Replenish tokens: rate * elapsed / 1e9 */
    __u64 add_tokens = (elapsed_ns * RATE_BYTES_PER_SEC) / 1000000000ULL;
    if (add_tokens > 0) {
        __u64 new_tokens = state->tokens + add_tokens;
        if (new_tokens > BURST_CAPACITY)
            new_tokens = BURST_CAPACITY;
        state->tokens = new_tokens;
    }

    /* --- Packet Length Calculation --- */
    __u16 pkt_len = (void *)(ip + 1) - data; /* wire bytes from Ethernet start */
    /* Adjust: subtract Ethernet header and IP header options if any.
       For simplicity and verifier safety, use the IP total length field. */
    __u16 ip_total_len = bpf_ntohs(ip->tot_len);

    /* --- Token Check and Enforcement --- */
    if (ip_total_len > BURST_CAPACITY) {
        /* Packet exceeds burst capacity -> drop */
        bpf_map_update_elem(&policer_map, &src_ip, state, BPF_ANY);
        return XDP_DROP;
    }

    if (state->tokens < ip_total_len) {
        /* Insufficient tokens -> drop */
        bpf_map_update_elem(&policer_map, &src_ip, state, BPF_ANY);
        return XDP_DROP;
    }

    /* --- Token Deduction and Pass --- */
    state->tokens -= ip_total_len;
    bpf_map_update_elem(&policer_map, &src_ip, state, BPF_ANY);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
