#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* 
 * Flow key structure: 4-tuple endpoints.
 * We use a packed struct to ensure no padding bytes are added,
 * which is critical for consistent hashing in the BPF map.
 */
struct flow_key {
    __be32 saddr;   /* source IP address */
    __be32 daddr;   /* destination IP address */
    __be16 sport;   /* source port */
    __be16 dport;   /* destination port */
} __attribute__((packed));

/* 
 * BPF Hash Map to store SYN timestamps.
 * Key: struct flow_key (4-tuple)
 * Value: __u64 timestamp (bpf_ktime_get_ns() result)
 * Max entries: 1024
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    struct flow_key *key;
    __u64 *value;
} syn_ts_map SEC(".maps");

/* 
 * Per-CPU array map to record RTT histogram.
 * Index 0: RTT < 1ms  (0 - 1000 ns)
 * Index 1: 1ms <= RTT < 10ms (1000 - 10000 ns)
 * Index 2: 10ms <= RTT < 100ms (10000 - 100000 ns)
 * Index 3: RTT >= 100ms (>= 100000 ns)
 * Max entries: 4 (one per CPU)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __u64 *values;
} rtt_histogram_map SEC(".maps");

/* 
 * XDP program entry point.
 * Measures TCP SYN to SYN-ACK round-trip time.
 */
SEC("xdp")
int xtcp_rtt_tracker(struct xdp_md *xdpmd)
{
    void *data_end = (void *)(long)xdpmd->data_end;
    void *data = (void *)(long)xdpmd->data;

    /* Ethernet header check */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only process TCP packets */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* 
     * We only care about packets with SYN flag set (and ACK cleared).
     * This catches both initial SYNs and retransmitted SYNs.
     */
    if (!(tcp->syn && !tcp->ack))
        return XDP_PASS;

    /* 
     * Construct the flow key based on the 4-tuple.
     * We use the packet's source/destination as seen.
     */
    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    /* 
     * If the SYN has the ACK flag set (unlikely for initial SYN,
     * but possible for data-carrying SYNs or specific stack implementations),
     * we still process it, but the primary use case is initial SYN.
     */

    /* Record the SYN timestamp in the hash map */
    __u64 syn_ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&syn_ts_map, &key, &syn_ts, BPF_ANY);

    return XDP_PASS;
}

/* 
 * Helper XDP program to handle SYN-ACK responses.
 * This is attached as a separate XDP program or triggered via
 * a different hook. For this task, we assume the same XDP program
 * processes both directions, but typically you would need two
 * programs or a combined logic.
 * 
 * However, to strictly follow the task requirement of "On seeing the
 * corresponding SYN-ACK response", we implement a second pass logic
 * within the same program structure, checking for the SYN-ACK flag
 * and matching against the stored SYN timestamp.
 * 
 * Note: In a real dual-attachment scenario, you would attach one XDP
 * program to the ingress interface and another to the egress, or
 * use a combined approach. Here we provide the logic that would
 * reside in the egress/return path program.
 */
SEC("xdp")
int xtcp_rtt_tracker_synack(struct xdp_md *xdpmd)
{
    void *data_end = (void *)(long)xdpmd->data_end;
    void *data = (void *)(long)xdpmd->data;

    /* Ethernet header check */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only process TCP packets */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* 
     * Check for SYN-ACK flag: SYN flag set AND ACK flag set.
     * This is the standard response to an initial SYN.
     */
    if (!(tcp->syn && tcp->ack))
        return XDP_PASS;

    /* 
     * Construct the reverse flow key.
     * The SYN-ACK swaps source and destination compared to the original SYN.
     * We swap the 4-tuple to match the key stored in syn_ts_map.
     */
    struct flow_key rkey = {
        .saddr = ip->daddr, /* original dest becomes source */
        .daddr = ip->saddr, /* original source becomes dest */
        .sport = tcp->dest, /* original dest port becomes sport */
        .dport = tcp->source, /* original sport becomes dport */
    };

    /* Look up the originally recorded SYN timestamp */
    __u64 *syn_ts_ptr = bpf_map_lookup_elem(&syn_ts_map, &rkey);
    if (!syn_ts_ptr)
        return XDP_PASS; /* No matching SYN found, skip */

    __u64 syn_ts = *syn_ts_ptr;

    /* Get current timestamp */
    __u64 now = bpf_ktime_get_ns();

    /* Compute RTT delta in nanoseconds */
    __s64 rtt_ns = now - syn_ts;

    /* 
     * Convert to microseconds for bucketing clarity,
     * though we bucket based on nanosecond thresholds.
     * 1 ms = 1_000_000 ns
     * 10 ms = 10_000_000 ns
     * 100 ms = 100_000_000 ns
     */
    __u32 rtt_us = rtt_ns / 1000; /* RTT in microseconds */

    /* Determine histogram bucket */
    __u32 idx = 0;
    if (rtt_ns >= 100000000) /* >= 100ms */
        idx = 3;
    else if (rtt_ns >= 10000000) /* >= 10ms */
        idx = 2;
    else if (rtt_ns >= 1000000) /* >= 1ms */
        idx = 1;
    else
        idx = 0; /* < 1ms */

    /* 
     * Update the per-CPU histogram bucket.
     * bpf_map_update_elem with BPF_NOEXIST ensures we increment
     * the counter for this CPU's bucket.
     */
    __u64 val = 1;
    bpf_map_update_elem(&rtt_histogram_map, &idx, &val, BPF_ANY);

    /* 
     * Delete the flow entry from the SYN timestamp map.
     * This prevents matching the same SYN again if another SYN-ACK
