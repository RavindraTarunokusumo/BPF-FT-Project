#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 
 * Per-TEID quota statistics structure.
 * Packed to ensure correct alignment in the BPF hash map.
 */
struct teid_quota_stat {
    __u64 bytes_consumed;
    __u64 pkts_consumed;
};

/* 
 * Hash map keyed by TEID (__u32), storing per-TEID quota statistics.
 * max_entries 1024 as required.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct teid_quota_stat);
} teid_quota_map SEC(".maps");

/* 
 * GTP-U G-PDU message type constant.
 * Control messages have msg_type != 0xFF.
 */
#define GTPU_G_PDU_MSG_TYPE 0xFF

/*
 * XDP program entry point.
 * Enforces cumulative byte quota per GTP-U tunnel (TEID).
 * - Parses Ethernet, IP, and UDP headers.
 * - Identifies GTP-U G-PDU packets (UDP port 2152, msg_type == 0xFF).
 * - Accumulates wire bytes per TEID from the outer IP total length.
 * - Drops packets if cumulative bytes for that TEID exceed 102,400 bytes.
 * - Passes all other traffic (control messages, non-GTP-U, malformed).
 */
SEC("xdp")
int xdp_teid_quota_enforcer(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 
     * Basic frame length check: ensure we have enough data for Ethernet header.
     * We need at least sizeof(struct ethhdr) bytes.
     */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* 
     * Verify Ethernet type is IPv4 (0x0800). 
     * Other frame types are passed through.
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);

    /* 
     * Verify IP header fits within the frame.
     * ip->ihl is in 4-byte units; minimum is 5 (20 bytes).
     */
    if (ip + ip->ihl > data_end)
        return XDP_PASS;

    /* 
     * Must be UDP protocol (protocol field = 17).
     * Non-UDP traffic is passed through.
     */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 
     * UDP header check: need at least 8 bytes (source + dest port + length + checksum).
     * UDP header starts after IP header.
     */
    if (data + sizeof(struct ethhdr) + ip->ihl + 8 > data_end)
        return XDP_PASS;

    struct udphdr *udp = data + sizeof(struct ethhdr) + ip->ihl;

    /* 
     * Check destination UDP port is 2152 (GTP-U).
     * Use bpf_ntohs for byte-order conversion.
     */
    if (bpf_ntohs(udp->dest) != 2152)
        return XDP_PASS;

    /* 
     * GTP-U header check.
     * GTP-U header is 8 bytes: 
     *   - Version (3 bits) + PT (3 bits) + Reserved (1 bit) + NS (1 bit) + MT (1 bit) + Message Type (8 bits)
     *   - Length (24 bits)
     *   - TEID (32 bits)
     *   - Sequence Number (32 bits)
     *   - NS (8 bits) + Next Ext (8 bits) + MD (8 bits) + HF (8 bits)
     * For G-PDU, msg_type == 0xFF.
     * We need at least 8 bytes of GTP-U header after the UDP header.
     */
    if (data + sizeof(struct ethhdr) + ip->ihl + sizeof(struct udphdr) + 8 > data_end)
        return XDP_PASS;

    /* 
     * Parse GTP-U header fields.
     * Using union to safely access the first 8 bytes.
     */
    union {
        __u8 raw[8];
        struct {
            __u8 version_pt_reserved_ns_mt_msg_type;
            __u32 length_teid;
            __u32 seq_ns_md_hf;
        } gtp;
    } gtp_hdr;

    /* Copy GTP-U header from packet data */
    bpf_probe_read_kernel(&gtp_hdr, sizeof(gtp_hdr),
                          data + sizeof(struct ethhdr) + ip->ihl + sizeof(struct udphdr));

    /* 
     * Check if this is a G-PDU user plane packet.
     * msg_type is bits 0-7 of the first byte.
     * We extract it by shifting right 0 bits (already in position) and masking.
     * Actually, the first byte contains: version(3) | pt(3) | reserved(1) | ns(1) | mt(1) | msg_type(8).
     * The msg_type occupies the least significant 8 bits.
     * However, standard GTP-U msg_type is in bits 0-7 of the first octet after the version/pt etc.
     * For simplicity and correctness per spec: msg_type == 0xFF means G-PDU.
     * We mask the first byte with 0xFF to ensure we only check the lower 8 bits.
     */
    __u8 msg_type = gtp_hdr.gtp.version_pt_reserved_ns_mt_msg_type & 0xFF;

    if (msg_type != GTPU_G_PDU_MSG_TYPE) {
        /* 
         * Control message (msg_type != 0xFF). 
         * Pass through without quota enforcement.
         */
        return XDP_PASS;
    }

    /* 
     * Extract TEID from GTP-U header.
     * TEID is in the second 4-byte field (bits 0-31 of length_teid).
     * We use bpf_ntohl to convert from network to host byte order.
     */
    __u32 teid = bpf_ntohl(gtp_hdr.gtp.length_teid) & 0xFFFFFFFF;

    /* 
     * The outer IP total length (ip->tot_len) represents the entire IP packet size,
     * including IP header and payload (UDP + GTP-U). This is the wire byte count
     * we accumulate per the requirement "accumulate packet wire bytes".
     */
    __u64 wire_bytes = bpf_ntohs(ip->tot_len);

    /* 
     * Look up existing quota statistics for this TEID from the hash map.
     * bpf_map_lookup_elem returns 0 on success, non-zero if key not found.
     * We use a pointer to the value and a zero-initialized fallback.
     */
    struct teid_quota_stat *stat;
    __u32 zero = 0;
    stat = bpf_map_lookup_elem(&teid_quota_map, &teid, &zero);

    /* 
     * If key not found, bpf_map_lookup_elem may not populate stat properly.
     * We handle by initializing a local stat and updating the map if needed,
     * or simply using the returned pointer which may be NULL-like if not found.
     * Standard pattern: check if update needed, but here we accumulate unconditionally
     * using a local variable and then update the map.
     */
    __u64 current_bytes = 0;
    __u64 current_pkts = 0;

    if (stat) {
        current_bytes = stat->bytes_consumed;
        current_pkts = stat->pkts_consumed;
    }

    /* 
     * Check if adding this packet would exceed the maximum quota of 102,400 bytes.
     * Quota is cumulative: if (current_bytes + wire_bytes > 102400) drop.
     */
    if (current_bytes + wire_bytes > 102400) {
        /* 
         * Drop the packet as it would exceed the quota.
         * Note: we do not update the quota stats for the dropped packet
         * to reflect that it was denied, maintaining the "consumed" count
         * only for accepted packets. Alternatively, one could count dropped
         * packets against quota; here we drop before consumption.
         */
        return XDP_DROP;
    }

    /* 
     * Accumulate the quota statistics.
     * current_bytes + wire_bytes is guaranteed <= 102400 here.
     */
    current_bytes += wire_bytes;
    current_pk
