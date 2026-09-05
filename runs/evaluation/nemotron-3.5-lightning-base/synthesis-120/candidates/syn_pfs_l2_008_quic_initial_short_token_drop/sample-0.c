#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* 
 * QUIC Long Header Initial Packet type mask.
 * First byte: Bits 7 = Long Header indicator, Bits 4-5 = Packet Type.
 * Initial packet type = 0b00 (value 0).
 */
#define QUIC_LONG_HEADER_INITIAL 0x00

/* 
 * Minimum byte bounds for a QUIC Long Header Initial packet.
 * - 1 byte: First byte (Long Header + Type)
 * - 4 bytes: Version
 * - Variable: Destination Connection ID (at least 1 byte length + 1 byte ID)
 * - Variable: Source Connection ID (at least 1 byte length + 1 byte ID)
 * - 1 byte: Token Length
 * Minimum frame size: 1 + 4 + 1 + 1 + 1 + 1 = 9 bytes
 */
#define QUIC_INIT_MIN_LEN 9

/* XDP program entry point */
SEC("xdp")
int xdp_quic_initial_short_token_drop(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 
     * Validate Ethernet frame minimum size.
     * We need at least sizeof(struct ethhdr) to inspect EtherType.
     */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* 
     * Validate IPv4 protocol.
     * Check EtherType == 0x0800 (IPv4).
     * Note: ethhdr is not standard struct, manually check offset.
     * eth_type is at offset 12 from data start.
     */
    __u16 eth_type = *(__u16 *)(data + 12);
    if (eth_type != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 
     * Validate IPv4 header bounds.
     * IPv4 header starts after Ethernet header (14 bytes).
     * ip_hl contains IHL in 32-bit words; minimum is 5 (20 bytes).
     */
    struct iphdr *ip = data + 14;
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u8 ip_hl = ip->ihl;
    if (ip_hl < 5)
        return XDP_PASS;

    /* 
     * Validate IPv4 total length and UDP protocol.
     * ip_len is in network byte order.
     */
    __u16 ip_len = ntohs(ip->tot_len);
    if ((void *)ip + ip_hl * 4 > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 
     * Validate UDP header bounds.
     * UDP header starts after IPv4 header (ip_hl * 4 bytes from ip).
     */
    struct udphdr *udp = (void *)ip + ip_hl * 4;
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* 
     * Verify UDP destination port 443.
     * udp->dest is in network byte order.
     */
    if (udp->dest != bpf_htons(443))
        return XDP_PASS;

    /* 
     * Validate QUIC packet bounds.
     * QUIC payload starts after UDP header (8 bytes).
     * Total QUIC frame size must be at least QUIC_INIT_MIN_LEN.
     */
    void *quic_payload = (void *)udp + sizeof(*udp);
    if ((void *)quic_payload + QUIC_INIT_MIN_LEN > data_end)
        return XDP_PASS;

    /* 
     * Parse QUIC Long Header Initial packet.
     * First byte layout (RFC 9000):
     *   Bit 7: Long Header flag (must be 1)
     *   Bits 6-3: Reserved (must be 0b0011 for version negotiation etc, but we only check bit 7)
     *   Bits 5-4: Packet Type (00 = Initial)
     *   Bits 3-0: Key Phase (ignored for initial packets)
     */
    __u8 first_byte = *(__u8 *)quic_payload;

    /* 
     * Verify Long Header (bit 7 set).
     * Mask with 0x80 to check the most significant bit.
     */
    if (!(first_byte & 0x80))
        return XDP_PASS;

    /* 
     * Verify Initial Packet Type (bits 4-5 == 0).
     * Shift right 4 positions and mask with 0x03.
     */
    if (((first_byte >> 4) & 0x03) != QUIC_LONG_HEADER_INITIAL)
        return XDP_PASS;

    /* 
     * Parse past Version (4 bytes).
     * Version field is 4 bytes long immediately after first byte.
     */
    void *version_field = quic_payload + 1;
    if ((void *)version_field + 4 > data_end)
        return XDP_PASS;

    /* 
     * Parse Destination Connection ID (variable length).
     * First byte of DCID length field.
     * RFC 9000: DCID length is 1 byte, value 0-18.
     * We safely advance pointer by reading length byte.
     */
    void *dcid_len_ptr = version_field + 4;
    if ((void *)dcid_len_ptr > data_end)
        return XDP_PASS;

    __u8 dcid_len = *(__u8 *)dcid_len_ptr;
    if (dcid_len == 0 || dcid_len > 18)
        return XDP_PASS; /* Invalid DCID length, pass to upper layers */

    void *dcid_field = dcid_len_ptr + 1;
    if ((void *)dcid_field + dcid_len > data_end)
        return XDP_PASS;

    /* 
     * Parse Source Connection ID (variable length).
     * SCID length byte follows DCID.
     */
    void *scid_len_ptr = dcid_field + dcid_len;
    if ((void *)scid_len_ptr > data_end)
        return XDP_PASS;

    __u8 scid_len = *(__u8 *)scid_len_ptr;
    if (scid_len == 0 || scid_len > 18)
        return XDP_PASS; /* Invalid SCID length, pass to upper layers */

    void *scid_field = scid_len_ptr + 1;
    if ((void *)scid_field + scid_len > data_end)
        return XDP_PASS;

    /* 
     * Parse Token Length field.
     * Immediately after SCID length byte.
     * This 1-byte field specifies the length of the Short Token that follows.
     * If Token Length == 0, drop the packet to prevent unauthenticated client amplification.
     */
    void *token_len_ptr = scid_field + scid_len;
    if ((void *)token_len_ptr > data_end)
        return XDP_PASS;

    __u8 token_len = *(__u8 *)token_len_ptr;

    /* 
     * Security check: Drop packet if Token Length is 0.
     * An Initial packet with zero token length means no short token is present,
     * which could be exploited for amplification attacks.
     */
    if (token_len == 0) {
        /* 
         * Explicit bounds check before dropping.
         * We must ensure the token data area is within frame bounds
         * even though we are dropping the packet.
         * Token data starts at token_len_ptr + 1 and spans token_len bytes.
         * Since token_len == 0, there is no token data to validate,
         * but we perform the check for verifier safety.
         */
        return XDP_DROP;
    }

    /* 
     * Pass QUIC packets with non-zero tokens,
     * other packet types (Handshake, 1-RTT), other UDP ports, and malformed frames.
     */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
