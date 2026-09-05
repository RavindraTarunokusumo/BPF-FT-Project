/* XDP program: Synthesize ICMP Destination Unreachable / Port Unreachable
 * (Type 3, Code 3) for IPv4 UDP traffic targeting closed port 9999.
 *
 * Behavior:
 *   - Validates Ethernet, IPv4, and UDP header bounds.
 *   - If UDP destination port == 9999: swaps MACs, swaps IPv4 endpoints,
 *     sets IP protocol to IPPROTO_ICMP, constructs ICMP Type 3 Code 3,
 *     recalculates IPv4 and ICMP checksums, returns XDP_TX.
 *   - Otherwise: passes traffic unchanged (XDP_PASS).
 *
 * Compilation: clang -target bpf -O2 -c xdp_icmp_port_unreach.c -o xdp_icmp_port_unreach.o
 * License: GPL
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/ctx/sk_buff.h>
#include <bpf/ctx/rewrite.h>

#define TARGET_PORT bpf_htons(9999)

/* Helper: load 16-bit value in a safe manner */
static __always_inline __u16 load_u16(const void *ptr)
{
    return *(const __u16 *)ptr;
}

/* Helper: store 16-bit value */
static __always_inline void store_u16(void *ptr, __u16 val)
{
    *(__u16 *)ptr = val;
}

/* Helper: load 32-bit value in a safe manner */
static __always_inline __u32 load_u32(const void *ptr)
{
    return *(const __u32 *)ptr;
}

/* Helper: store 32-bit value */
static __always_inline void store_u32(void *ptr, __u32 val)
{
    *(__u32 *)ptr = val;
}

/* Ethernet checksum pseudo-header helper (IP header fields) */
static __always_inline __u16 ip_checksum(__u16 *addr, int count)
{
    __u32 sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0)
        sum += *(__u8 *)addr;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

/* Ethernet checksum over pseudo-header + payload */
static __always_inline __u16 tcp_udp_checksum(struct __sk_buff *skb,
                                              struct iphdr *ip,
                                              void *transport,
                                              int transport_len)
{
    struct {
        __u32 src_ip;
        __u32 dst_ip;
        __u8 zero;
        __u8 protocol;
        __u16 transport_len;
    } pseudo_hdr = {
        .src_ip = load_u32(&ip->saddr),
        .dst_ip = load_u32(&ip->daddr),
        .zero = 0,
        .protocol = IPPROTO_UDP,
        .transport_len = bpf_htonl(transport_len),
    };

    /* Build pseudo-header + transport header */
    int total = sizeof(pseudo_hdr) + transport_len;
    __u16 *buf = (__u16 *)bpf_xdp_adjust_head(skb, -(int)sizeof(pseudo_hdr));
    if (buf == NULL)
        return 0; /* adjustment failed */

    /* Copy pseudo-header at the start */
    store_u32(&buf[0], pseudo_hdr.src_ip);
    store_u32(&buf[2], pseudo_hdr.dst_ip);
    buf[4] = pseudo_hdr.zero;
    buf[5] = (pseudo_hdr.protocol << 24) | bpf_htonl(pseudo_hdr.transport_len) & 0x00ffffff;

    /* Transport header follows pseudo-header */
    /* Note: transport pointer is relative to original skb data, we adjust offset */
    return ip_checksum(buf, total);
}

SEC("xdp")
int xdp_icmp_port_unreach(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Validate Ethernet frame minimum size */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate IPv4 protocol identifier */
    /* We only process IPv4; other EtherTypes are passed through */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Validate IPv4 header length (ihl * 4) and minimum 20 bytes */
    if (ip->ihl < 5)
        return XDP_PASS;
    int ip_hdr_len = ip->ihl * 4;
    if (data + sizeof(*eth) + ip_hdr_len > data_end)
        return XDP_PASS;

    /* 4. Check protocol == IPPROTO_UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 5. Validate UDP header after IPv4 header */
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* 6. Check UDP destination port == 9999 */
    if (udp->dest != TARGET_PORT)
        return XDP_PASS;

    /* --- At this point: we have a UDP packet to port 9999 --- */

    /* 7. Swap Ethernet MAC addresses */
    /* eth->h_source is current src, eth->h_dst is current dst */
    __u64 tmp = eth->h_source.addr[0];
    eth->h_source.addr[0] = eth->h_dst.addr[0];
    eth->h_dst.addr[0] = tmp;
    tmp = eth->h_source.addr[1];
    eth->h_source.addr[1] = eth->h_dst.addr[1];
    eth->h_dst.addr[1] = tmp;
    tmp = eth->h_source.addr[2];
    eth->h_source.addr[2] = eth->h_dst.addr[2];
    eth->h_dst.addr[2] = tmp;
    /* Note: full 6-byte swap can be done byte-by-byte; here we swap 3 u64s
     * covering the 6 bytes (first 2 u64s are 12 bytes, last u64 has 2 bytes valid).
     * For simplicity and safety, we perform a byte-level swap.
     */
    {
        __u8 tmp_mac[6];
        bpf_probe_read_kernel(tmp_mac, 6, &eth->h_source.addr);
        bpf_probe_read_kernel(&eth->h_source.addr, 6, &eth->h_dst.addr);
        bpf_probe_write_kernel(&eth->h_source.addr, tmp_mac, 6);
        /* Actually, let's do it the simple way with memmove semantics via bpf helpers
         * but we can just swap the first 6 bytes directly.
         */
    }

    /* Simpler byte-swap approach for MAC */
    {
        __u8 src[6], dst[6];
        bpf_probe_read_kernel(src, 6, &eth->h_source.addr);
        bpf_probe_read_kernel(dst, 6, &eth->h_dst.addr);
        bpf_probe_write_kernel(&eth->h_source.addr, dst, 6);
        bpf_probe_write_kernel(&eth->h_dst.addr, src, 6);
    }

    /* 8. Swap IPv4 source and destination addresses */
    __u32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    /* 9. Set IP protocol to IPPROTO_ICMP */
    ip->protocol = IPPROTO_ICMP;

    /* 10. Construct ICMP Destination Unreachable / Port Unreachable (Type 3, Code 3)
     *    ICMP header follows IPv4 header.
     *    We need to append ICMP header after current IP header.
     *    Since we are modifying in-place, we adjust the transport header position.
     *    The ICMP header will be 8 bytes: type(1) code(1) checksum(2) unused(2) rest of data.
     *    For Type 3 Code 3, the first 8 bytes are: type=3, code=3, checksum, unused,
     *    followed by first 8 bytes of original UDP header (per RFC 79
