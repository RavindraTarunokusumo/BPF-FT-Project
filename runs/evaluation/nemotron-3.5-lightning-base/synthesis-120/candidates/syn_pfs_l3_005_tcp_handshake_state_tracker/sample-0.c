#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 
 * Flow key structure: 4-tuple endpoints 
 * Used as the key for the connection tracking hash map
 */
struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

/* 
 * Connection tracking states 
 * CLOSED: 0 - No connection or connection terminated
 * SYN_SENT: 1 - Sent SYN, waiting for SYN-ACK 
 * ESTABLISHED: 2 - Connection fully established
 */
#define CLOSED      0
#define SYN_SENT    1
#define ESTABLISHED 2

/* 
 * Connection tracking hash map 
 * Key: struct flow_key (4-tuple endpoints) 
 * Value: __u32 state 
 * Max entries: 2048
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct flow_key);
    __type(value, __u32);
} ct_map SEC(".maps");

/* 
 * XDP program entry point 
 * Processes incoming packets for stateful TCP connection tracking
 */
SEC("xdp")
int xdp_conn_tracker(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 
     * Basic frame validation: ensure we have enough data 
     * for Ethernet header + IP header + TCP header 
     */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 
     * Validate Ethernet type - only process IPv4 
     * Other frame types are passed through
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 
     * Only process TCP protocol 
     * UDP and other protocols are passed through
     */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 
     * Validate TCP header fits within the frame 
     * TCP header length is in 32-bit words, so multiply by 4
     */
    int tcp_header_len = ip->ihl * 4;
    if (tcp_header_len < sizeof(struct tcphdr))
        return XDP_PASS;

    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + tcp_header_len > data_end)
        return XDP_PASS;

    /* 
     * Build the flow key using 4-tuple endpoints 
     * Key: { src_ip, dst_ip, src_port, dst_port }
     */
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest
    };

    /* 
     * Get current state from connection tracking map 
     * If flow not found, state defaults to CLOSED (0)
     */
    __u32 *state = bpf_map_lookup_elem(&ct_map, &key);
    __u32 cur_state = (state ? *state : CLOSED);

    /* 
     * Extract TCP flags 
     * FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10, URG: 0x20
     */
    __u16 flags = tcp->syn | (tcp->ack << 1) | (tcp->fin << 2) | (tcp->rst << 3);

    /* 
     * === STATE MACHINE: 3-WAY HANDSHAKE === 
     */

    /* 
     * SYN packet: Initialize forward direction state 
     * SYN has no ACK flag set (ack == 0)
     */
    if (tcp->syn && !tcp->ack) {
        /* 
         * SYN received - initialize state to SYN_SENT (1) 
         * This represents the forward direction (client -> server)
         */
        bpf_map_update_elem(&ct_map, &key, &SYN_SENT, BPF_ANY);
        bpf_printk("XDP: SYN received, flow %pI4:%d -> %pI4:%d set to SYN_SENT\n",
                   &ip->saddr, ntohs(tcp->source),
                   &ip->daddr, ntohs(tcp->dest));
        return XDP_PASS;
    }

    /* 
     * SYN-ACK packet: Promote both directions to ESTABLISHED 
     * SYN-ACK has both SYN and ACK flags set
     */
    if (tcp->syn && tcp->ack) {
        /* 
         * SYN-ACK received - promote both directions to ESTABLISHED (2) 
         * We update the map with the same key since directionality 
         * is tracked by the endpoint perspective
         */
        __u32 est_state = ESTABLISHED;
        bpf_map_update_elem(&ct_map, &key, &est_state, BPF_ANY);
        bpf_printk("XDP: SYN-ACK received, flow %pI4:%d -> %pI4:%d set to ESTABLISHED\n",
                   &ip->saddr, ntohs(tcp->source),
                   &ip->daddr, ntohs(tcp->dest));
        return XDP_PASS;
    }

    /* 
     * FIN or RST packet: Transition to CLOSED state 
     * FIN: Normal connection termination (fin flag set)
     * RST: Reset connection (rst flag set)
     */
    if (tcp->fin || tcp->rst) {
        /* 
         * Teardown - set state to CLOSED (0) 
         * This removes the flow tracking entry
         */
        __u32 closed_state = CLOSED;
        bpf_map_update_elem(&ct_map, &key, &closed_state, BPF_ANY);
        bpf_printk("XDP: FIN/RST received, flow %pI4:%d -> %pI4:%d set to CLOSED\n",
                   &ip->saddr, ntohs(tcp->source),
                   &ip->daddr, ntohs(tcp->dest));
        return XDP_PASS;
    }

    /* 
     * === ESTABLISHED STATE HANDLING === 
     * 
     * For traffic in ESTABLISHED state (state == 2), pass the packet 
     * This includes ACK packets, data packets, and other TCP traffic
     */

    /* 
     * If flow is in ESTABLISHED state, pass the packet 
     */
    if (cur_state == ESTABLISHED) {
        bpf_printk("XDP: ESTABLISHED flow %pI4:%d -> %pI4:%d passing traffic\n",
                   &ip->saddr, ntohs(tcp->source),
                   &ip->daddr, ntohs(tcp->dest));
        return XDP_PASS;
    }

    /* 
     * === UNSOLICITED TCP TRAFFIC DROP === 
     * 
     * If non-SYN TCP traffic arrives for a flow with no established state, 
     * drop the packet with XDP_DROP 
     * 
     * This covers:
     * - ACK packets without established state (SYN not received yet)
     * - Data packets without established state
     * - Any TCP traffic not tracked in ct_map
     */
    bpf_printk("XDP: DROPPING unsolicited TCP for flow %pI4:%d -> %pI4:%d (state=%u)\n",
               &ip->saddr, ntohs(tcp->source),
               &ip->daddr, ntohs(tcp->dest),
               cur_state);
    return XDP_DROP;
}

/* 
 * GPL license declaration required for XDP programs 
 * This declares the program as GPL licensed
 */
char LICENSE[] SEC("license") = "GPL";
