#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 
 * Per-source IPv4 state for SYN flood rate limiting.
 * window_start_ns: timestamp (ns) when the current 100ms window began.
 * syn_count: number of SYN packets seen from this source in the current window.
 * drop_count: number of SYN packets dropped from this source.
 */
struct syn_rate_state {
    __u64 window_start_ns;
    __u32 syn_count;
    __u32 drop_count;
};

/* 
 * BPF hash map keyed by source IPv4 address (__be32).
 * max_entries 1024 as required.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct syn_rate_state);
} syn_flood_map SEC(".maps");

/* 
 * XDP program entry point.
 * Protects against TCP SYN flood attacks using a per-source sliding window rate limit.
 */
SEC("xdp")
int xdp_syn_flood_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 
     * Verify we have enough data for Ethernet header.
     * struct eth_hdr is 14 bytes minimum.
     */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 
     * IPv4 protocol check.
     * We only process IPv4 packets; pass everything else.
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 
     * Only process TCP protocol (IPPROTO_TCP = 6).
     * Other protocols pass through.
     */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 
     * TCP header starts after the IPv4 header.
     * IPv4 header length is in ip->ihl (4-byte words), so actual bytes = ihl * 4.
     */
    void *tcp_start = data + sizeof(*eth) + (ip->ihl * 4);
    if (tcp_start + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = tcp_start;

    /* 
     * Filter: only initial TCP SYNs (syn == 1 && ack == 0).
     * ACK packets, SYN-ACK, and data-carrying segments are passed through.
     */
    if (!(tcp->syn && !tcp->ack))
        return XDP_PASS;

    /* 
     * Get source IP address from the IP header.
     * ip->saddr is stored in network byte order; bpf_map_lookup expects __be32 key,
     * which matches naturally.
     */
    __be32 src_ip = ip->saddr;

    /* 
     * Retrieve or create per-source state from the hash map.
     * bpf_map_lookup_elem returns 1 on success, 0 on miss.
     * On miss, bpf_map_update_elem with BPF_ANY creates the entry zeroed.
     */
    struct syn_rate_state *state;
    u32 key = src_ip; /* key is already __be32, no conversion needed */
    int map_err = bpf_map_lookup_elem(&syn_flood_map, &key, &state);

    if (!map_err) {
        /* First SYN from this source: initialize window start timestamp. */
        state->window_start_ns = bpf_ktime_get_ns();
        state->syn_count = 1;
        state->drop_count = 0;
    } else {
        /* 
         * Existing entry: check if we are still within the same 100ms window.
         * 100ms = 100,000,000 ns.
         */
        __u64 now = bpf_ktime_get_ns();
        if (now - state->window_start_ns >= 100000000) {
            /* 
             * Window expired: reset counters for a new window.
             * This implements a sliding window: the new window starts at 'now'.
             */
            state->window_start_ns = now;
            state->syn_count = 1;
            state->drop_count = 0;
        }
        /* 
         * Increment SYN count for the current window.
         * Note: This is not atomic; in a real production system atomic operations
         * or per-CPU maps would be required for concurrent XDP execution.
         */
        state->syn_count++;
    }

    /* 
     * Enforce the limit: allow up to 10 SYNs per 100ms window.
     * If syn_count exceeds 10, increment drop_count and drop the packet.
     */
    if (state->syn_count > 10) {
        state->drop_count++;
        return XDP_DROP;
    }

    /* 
     * Within limit: allow the packet through.
     */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
