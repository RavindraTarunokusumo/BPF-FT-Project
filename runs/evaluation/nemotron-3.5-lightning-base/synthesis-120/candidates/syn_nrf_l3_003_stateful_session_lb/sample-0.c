#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Define the flow key structure.
 * We use source and destination IP addresses and ports to identify a connection.
 * The struct must be packed to avoid padding bytes that could affect hash consistency.
 */
struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

/* BPF hash map to store session affinity.
 * Key: struct flow_key
 * Value: __u32 ifindex of the assigned backend
 * max_entries: 1024
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, __u32);
} session_map SEC(".maps");

/* XDP program entry point.
 * Handles TCP session load balancing with sticky affinity.
 */
SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Parse Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process TCP protocol */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* Check for SYN flag to establish new session affinity */
    if (tcp->syn && !tcp->ack) {
        /* Build flow key from TCP quadruple */
        struct flow_key key = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = tcp->source,
            .dst_port = tcp->dest,
        };

        /* Compute hash index from the flow key.
         * We use BPF helper bpf_lfsr_random() for a simple but effective hash.
         * The result is masked to fit within max_entries (1023).
         */
        __u32 hash = bpf_lfsr_random();
        __u32 idx = hash & (1024 - 1); /* modulo 1024 */

        /* Assign backend interface index: 50 + (hash % 2).
         * This gives two possible backends: 50 or 51.
         * The result is stored as __u32 ifindex.
         */
        __u32 ifindex = 50 + (hash & 1);

        /* Store the session affinity in the hash map.
         * BPF_MAP_TYPE_HASH stores value per key; overwriting is allowed.
         */
        bpf_map_update_elem(&session_map, &key, &ifindex, BPF_ANY);

        /* Redirect the SYN packet to the assigned backend.
         * bpf_redirect takes the ifindex and flags (0 for normal redirect).
         */
        return bpf_redirect(ifindex, 0);
    }

    /* For established packets (SYN+ACK or data), lookup existing session affinity.
     * We build the same flow key structure to search the map.
     */
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    __u32 *stored_ifindex;
    stored_ifindex = bpf_map_lookup_elem(&session_map, &key);
    if (stored_ifindex) {
        /* Packet belongs to an existing session; redirect to the assigned backend. */
        return bpf_redirect(*stored_ifindex, 0);
    }

    /* If no affinity found for this flow, pass the packet normally.
     * This can happen for the first packet of a connection if SYN was missed
     * or for packets outside tracked flows.
     */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
