#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 
 * Flow key structure: 
 * We use source/destination IP addresses and ports to identify a TCP flow.
 * This allows per-flow sequence tracking.
 */
struct flow_key {
    __u32 saddr;      /* Source IP address */
    __u32 daddr;      /* Destination IP address */
    __u16 sport;      /* Source port */
    __u16 dport;      /* Destination port */
};

/*
 * Sequence tracker structure:
 * - expected_seq: The sequence number we expect to see next for in-order delivery
 * - in_order_pkts: Counter of packets arriving in correct sequence order
 * - out_of_order_pkts: Counter of packets arriving out of sequence
 */
struct seq_tracker {
    __u32 expected_seq;
    __u32 in_order_pkts;
    __u32 out_of_order_pkts;
};

/* 
 * BPF hash map to store per-flow sequence tracking state.
 * max_entries 1024 as required.
 * The map uses the flow_key as the key and seq_tracker as the value.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    struct flow_key *key;
    struct seq_tracker *value;
} seq_tracker_map SEC(".maps");

/* 
 * XDP program entry point.
 * This program inspects every passing packet and tracks TCP sequence continuity.
 * It always returns XDP_PASS to allow normal packet processing to continue.
 */
SEC("xdp")
int xdp_seq_tracker(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 
     * Basic packet size check - we need at least an Ethernet header.
     * Without this, we risk out-of-bounds access when parsing lower layers.
     */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* 
     * Parse Ethernet header to determine IP protocol.
     * h_proto is network byte order (big-endian).
     */
    struct ethhdr *eth = data;
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    /* 
     * Parse IP header.
     * iph->ihl is in 32-bit words, so actual header length is ihl * 4.
     */
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    /* 
     * We only process IPv4 TCP. Check protocol field.
     * IPPROTO_TCP = 6
     */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 
     * Calculate TCP header start and validate we have enough data.
     * ip->ihl is the Internet Header Length in 32-bit words.
     */
    int ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    
    if ((void *)tcp + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    /* 
     * Check for payload presence.
     * TCP data starts after the TCP header.
     * tcp->doff is the TCP header length in 32-bit words.
     */
    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr))
        return XDP_PASS; /* Malformed TCP header */

    /* 
     * Calculate payload length.
     * Total packet length minus IP header minus TCP header.
     * We use ctx->len which is the total frame length from the driver.
     * However, for raw packet access via XDP, we need to be careful.
     * We calculate payload end based on our parsed pointers.
     */
    void *tcp_payload = (void *)tcp + tcp_hdr_len;
    
    /* 
     * Validate payload fits within the packet.
     * We check against data_end which is the actual buffer boundary.
     */
    if (tcp_payload + (ctx->len - ip_hdr_len - tcp_hdr_len) > data_end)
        return XDP_PASS; /* Payload extends beyond captured data */

    /* 
     * Calculate actual payload length.
     * ctx->len is the total packet length.
     * Payload = total - IP header - TCP header
     */
    __u32 payload_len = ctx->len - ip_hdr_len - tcp_hdr_len;
    
    /* 
     * Ensure payload_len doesn't exceed what's actually in the TCP segment.
     * The TCP header might not indicate all data is present (e.g., SYN/FIN consume seq numbers).
     * For simplicity, we use the calculated payload length from the packet buffer.
     */
    if (payload_len == 0)
        return XDP_PASS; /* No payload to track */

    /* 
     * Extract flow key fields from the packet.
     * We need to be careful about byte order - IP addresses are in network order,
     * ports are in network order.
     */
    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    /* 
     * Look up or create the per-flow sequence tracker.
     * bpf_map_lookup_elem returns 0 and sets val to zero if key not found,
     * which is perfect for initializing a new flow's tracker.
     */
    struct seq_tracker *tracker;
    tracker = bpf_map_lookup_elem(&seq_tracker_map, &key);
    if (!tracker) {
        /* Key not found - bpf_map_lookup_elem would have returned NULL or val=0 */
        /* Actually, we need to handle this: if tracker is NULL, we need to update */
        /* But bpf_map_lookup_elem returns the value pointer if found, else NULL */
        /* We need to use bpf_map_update_elem to create new entry */
        
        /* Allocate a new tracker value initialized to 0 */
        struct seq_tracker new_tracker = {0};
        
        /* Update the map with new key-value pair */
        if (bpf_map_update_elem(&seq_tracker_map, &key, &new_tracker, BPF_ANY) != 0)
            return XDP_PASS;
        
        /* Now look up the newly created entry */
        tracker = bpf_map_lookup_elem(&seq_tracker_map, &key);
        if (!tracker)
            return XDP_PASS;
    }

    /* 
     * Now we have the tracker for this flow.
     * Check if the TCP sequence number matches our expected value.
     * tcp->seq is the sequence number of the first byte in this segment.
     */
    if (tcp->seq == tracker->expected_seq) {
        /* 
         * Packet is in order - advance expected sequence by payload length
         * and increment the in-order counter.
         */
        tracker->expected_seq += payload_len;
        tracker->in_order_pkts++;
    } else {
        /* 
         * Packet is out of order - the sequence number doesn't match expected.
         * Increment the out-of-order counter.
         * Note: We do NOT advance expected_seq here, as the expected sequence
         * remains at what we were waiting for. The next in-order packet will
         * be checked against this same expected value.
         */
        tracker->out_of_order_pkts++;
    }

    /* 
     * Update the map with the modified tracker values.
     * BPF_ANY means update if key exists, or insert if it doesn't (though we
     * already ensured it exists above).
     */
    bpf_map_update_elem(&seq_tracker_map, &key, tracker, BPF_ANY);

    /* 
     * Always pass the packet to the next XDP program or network stack.
     * This program's purpose is telemetry/statistics collection only.
     */
    return XDP_PASS;
}

/* License declaration - GPL is required for XDP programs that use BGP helpers */
char LICENSE[] = "GPL";
