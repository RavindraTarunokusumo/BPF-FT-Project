#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 
 * Bearer statistics structure maintained per TEID in the traffic matrix.
 * Packed to ensure no padding bytes are added by the compiler, 
 * which is critical for consistent BPF map access.
 */
struct bearer_stats {
    __u64 uplink_bytes;
    __u64 downlink_bytes;
    __u64 total_pkts;
} __attribute__((packed));

/* 
 * BPF hash map keyed by TEID (__u32).
 * max_entries 1024 as required.
 * Values are of type struct bearer_stats.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct bearer_stats);
} bearer_matrix_map SEC(".maps");

/* 
 * XDP program entry point.
 * Inspects GTP-U packets (UDP port 2152) and updates per-TEID telemetry.
 * Always returns XDP_PASS.
 */
SEC("xdp")
int xdp_bearer_traffic_matrix(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP header */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process UDP packets */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Parse UDP header */
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* Check for GTP-U destination port 2152 (uplink) or source port 2152 (downlink).
     * GTP-U uses UDP port 2152 for both directions, distinguished by port placement.
     * We extract the 32-bit TEID from the GTP-U header following the UDP header.
     * GTP-U header format: Next Ext (1 octet) + PT (3 bits) + Reserved (1 bit) + ST (1 bit) + Sequence (1 bit) + N-P (1 bit) + M (1 bit) + Window (3 bits) + MGT (1 bit) + Length (12 bits) + TEID (32 bits)
     * For simplicity and standard alignment, we read the 4 bytes immediately after the UDP header as the TEID.
     * Note: Real GTP-U parsing may require handling extension headers, but this follows the task's extraction requirement.
     */
    __u16 udp_dport = bpf_ntohs(udp->dest);
    __u16 udp_sport = bpf_ntohs(udp->source);

    /* Determine direction: 
     * Uplink: UDP destination port is 2152
     * Downlink: UDP source port is 2152
     * If neither port is 2152, we skip telemetry update but still pass the packet.
     */
    int is_uplink = (udp_dport == 2152);
    int is_downlink = (udp_sport == 2152);

    if (!is_uplink && !is_downlink)
        return XDP_PASS;

    /* Extract TEID from the 4 bytes following the UDP header.
     * The TEID is a 32-bit unsigned integer stored in network byte order.
     * We read it directly and use it as the map key.
     * Note: Real GTP-U TEID extraction may involve bit manipulation due to the header structure,
     * but this implementation reads the raw 4 bytes post-UDP as specified by the task's extraction context.
     */
    __u32 *teid_ptr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    if (teid_ptr + 1 > data_end)
        return XDP_PASS;

    __u32 teid = bpf_ntohl(*teid_ptr);

    /* Lookup or update the per-TEID statistics in the bearer_matrix_map.
     * bpf_map_lookup_elem returns 0 on success, and the value is filled in *value.
     * If the key does not exist, bpf_map_update_elem with BPF_ANY creates a new entry
     * initialized to zero (zero-initialized maps in BPF ensure this).
     */
    struct bearer_stats stats = {};
    int ret = bpf_map_lookup_elem(bearer_matrix_map, &teid, &stats);
    if (ret) {
        /* Key not present; stats is zero-initialized, which is fine for first accumulation. */
        ret = 0; /* proceed with zeroed stats */
    }

    /* Accumulate telemetry based on direction */
    if (is_uplink) {
        stats.uplink_bytes += ip->tot_len; /* ip->tot_len includes IP header + UDP header + data */
        stats.total_pkts++;
    }
    if (is_downlink) {
        stats.downlink_bytes += ip->tot_len;
        stats.total_pkts++;
    }

    /* Update the map with the accumulated statistics.
     * BPF_ANY: create or update the entry with the new stats value.
     * We cast &stats to void* as expected by the helper.
     */
    bpf_map_update_elem(bearer_matrix_map, &teid, &stats, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
