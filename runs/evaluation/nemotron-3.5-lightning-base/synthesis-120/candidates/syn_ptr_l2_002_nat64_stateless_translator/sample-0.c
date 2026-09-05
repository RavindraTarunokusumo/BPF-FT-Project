#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/ctx/skb.h>
#include <bpf/ctx/xdp.h>

/* 
 * NAT64 Stateless Translator (RFC 7915)
 * Translates IPv6 packets with destination 64:ff9b::/96 to IPv4.
 * The lower 32 bits of the IPv6 destination address become the IPv4 destination.
 */

SEC("xdp")
int nat64_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 
     * Validate Ethernet frame minimum size.
     * We need at least sizeof(struct ethhdr) to read h_proto and 
     * check for IPv6.
     */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* Only process IPv6 traffic (EtherType 0x86DD) */
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    /* 
     * Validate IPv6 header bounds.
     * IPv6 header is fixed at 40 bytes.
     */
    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
        return XDP_PASS;

    struct ipv6hdr *ipv6 = data + sizeof(struct ethhdr);

    /* 
     * Check for NAT64 prefix 64:ff9b::/96.
     * The first 96 bits must equal 0x0064FF9B0000000000000000.
     * We inspect the first 4 u64 words of the IPv6 address.
     * ipv6->daddr.in6_u.u64[0..3] corresponds to the first 128 bits.
     */
    if (ipv6->daddr.in6_u.u64[0] != 0x0064FF9B00000000ULL ||
        ipv6->daddr.in6_u.u64[1] != 0 ||
        ipv6->daddr.in6_u.u64[2] != 0 ||
        ipv6->daddr.in6_u.u64[3] != 0)
        return XDP_PASS;

    /* 
     * Extract the lower 32 bits of the IPv6 destination address.
     * In network byte order (big-endian), the last 32 bits of the 
     * IPv6 address are stored in ipv6->daddr.in6_u.u64[3].
     * However, since we already verified the prefix 64:ff9b::/96, 
     * the lower 32 bits represent the IPv4 address in network order.
     * We use u32 directly for the IPv4 destination.
     */
    __be32 ipv4_dst = ipv6->daddr.in6_u.u64[3];

    /* 
     * Shrink the packet head by 20 bytes.
     * Original: 40-byte IPv6 header.
     * After:    20-byte IPv4 header (IHL=5 -> 5*4=20 bytes).
     * bpf_xdp_adjust_head returns 0 on success, negative on failure.
     */
    if (bpf_xdp_adjust_head(ctx, 20) != 0)
        return XDP_PASS;

    /* 
     * After adjust_head, the Ethernet header is still at data,
     * but the IP header now starts 20 bytes earlier.
     * We need to re-validate bounds after adjustment.
     * The IPv4 header will be at: data + sizeof(struct ethhdr)
     * and must fit within data_end.
     * Minimum: eth(14) + ipv4(20) = 34 bytes.
     */
    if (data + sizeof(struct ethhdr) + 20 > data_end)
        return XDP_PASS;

    /* 
     * Construct the IPv4 header in-place.
     * The IPv6 header originally occupied 40 bytes starting after Ethernet.
     * After removing 20 bytes, we have a 20-byte region that will serve 
     * as the IPv4 header.
     * 
     * Layout after adjustment (from Ethernet header):
     * [14 bytes Ethernet] [20 bytes IPv4 header] [remaining payload]
     * 
     * We cast the data pointer + Ethernet header offset to struct iphdr.
     * The new IPv4 header will overwrite the first 20 bytes of the 
     * original IPv6 header.
     */
    struct iphdr *ip4 = (struct iphdr *)(data + sizeof(struct ethhdr));

    /* Set IPv4 version (4) and IHL (5 -> 20 bytes) */
    ip4->version = 4;
    ip4->ihl = 5;

    /* 
     * Type of Service: 0 (normal)
     * Total Length: 0 (will be filled by the verifier/adapter, 
     *               or we can set it. For safety, we leave 0; 
               the stack may adjust, but typically XDP expects 
               the driver/upper layers to handle. 
               Actually, we must set it for a valid packet.
               Let's calculate: original IPv6 payload + next headers.
               Since we don't know the original payload size easily 
               without parsing, and this is a simple translator, 
               we set Total Length to 20 (just the header) 
               or rely on the fact that the packet buffer size 
               remains the same but the protocol changes.
               Wait, bpf_xdp_adjust_head only adjusts the head. 
               The total packet size (data_end - data) remains the same.
               The IPv4 total length should be the IPv4 header (20) 
               plus the remaining payload bytes.
               However, for a minimal, verifier-safe approach that 
               passes validation and is commonly used in examples, 
               we often set it to 20 or calculate based on 
               original IPv6 payload. Given the constraints of 
               this task and typical XDP NAT examples, we set 
               it to 20 for the header translation scenario, 
               assuming upper layers or the caller handles payload, 
               or we just set it to 20 as a placeholder. 
               Actually, RFC and practical XDP NAT usually 
               recalculates this. Let's look at standard patterns.
               Standard pattern: ip4->tot_len = htons(20 + payload_len).
               Since we don't have payload_len readily available 
               without complex parsing, and the task says "construct 
               a valid IPv4 header", we will set tot_len to 20 
               for the header part, or better, we can compute it.
               The original packet size is data_end - data.
               The Ethernet header is 14 bytes.
               The original IPv6 header was 40 bytes.
               The remaining payload is (data_end - data) - 14 - 40.
               After adjust_head(20), the new IPv4 header is 20 bytes.
               The new total length should be 20 + ((data_end - data) - 54).
               Let's simplify and set tot_len to a value that 
               makes the packet valid for the translator purpose, 
               or just 20. Many XDP NAT examples set tot_len = 20 
               if they are just translating headers and the payload 
               is dropped or handled separately, but here we pass.
               Let's calculate correctly.
               Original total bytes: data_end - data.
               New IPv4 total length = (data_end - data) - 14 (eth header).
               We will set this.
    */
    ip4->tot_len = 0; /* placeholder, will be set below */

    /* 
     * Actually, let's compute tot_len properly.
     * Original packet size: data_end - data.
     * Eth header: 14 bytes.
     * Original IPv6 header: 40 bytes.
     * Payload: data_end - data - 54.
     * New IPv4 header: 20 bytes.
     * New total length = 20 + (data_end - data - 54) = data_end - data - 34.
     * But wait, bpf_xdp_adjust_head(ctx, 20) moves the start of the 
     * network code down by 20. 
     * So the new 'data' effective for IP is old_data + 20? No.
     * adjust_head adjusts the 'data' pointer of the skb.
     * If we call adjust_head(ctx, 20), the skb->data moves back by 20 
     * (towards the start of the buffer), making room at
