/* XDP program: syn_pfs_l2_010_tcp_window_zero_drop
 *
 * Mitigates zero-window denial of service attacks by dropping established
 * TCP packets with a zero advertised receive window.
 *
 * - Validates Ethernet and IPv4 header bounds (variable IHL)
 * - Validates struct tcphdr bounds
 * - Drops packets where ACK is set, SYN and RST are clear, and window == 0
 * - Passes all other traffic (SYN, RST, non-zero window, UDP, ICMP, etc.)
 *
 * Compilation: clang -target bpf -c syn_pfs_l2_010_tcp_window_zero_drop.c -o syn_pfs_l2_010_tcp_window_zero_drop.o
 * License: GPL
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

/* Helper: load 16-bit network-order value safely */
static __always_inline __u16 load_u16_be(const void *ptr)
{
    return ((const __u8 *)ptr)[0] << 8 | ((const __u8 *)ptr)[1];
}

/* Helper: load 32-bit network-order value safely */
static __always_inline __u32 load_u32_be(const void *ptr)
{
    return ((const __u8 *)ptr)[0] << 24 | ((const __u8 *)ptr)[1] << 16 |
           ((const __u8 *)ptr)[2] << 8 | ((const __u8 *)ptr)[3];
}

SEC("xdp")
int xtcp_window_zero_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Parse Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate EtherType == IPv4 (0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Parse IPv4 header, respecting IHL (4 bytes * ihl) */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u8 ip_ihl = ip->ihl;
    if (ip_ihl < 5) /* minimum IHL is 5 (20 bytes) */
        return XDP_PASS;

    __u32 ip_header_len = ip_ihl * 4;
    if (data + sizeof(*eth) + ip_header_len > data_end)
        return XDP_PASS;

    /* 4. Validate protocol == IPPROTO_TCP (6) */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 5. Parse TCP header, respecting data_offset (doff) */
    struct tcphdr *tcp = (void *)ip + ip_header_len;
    if (data + sizeof(*eth) + ip_header_len + sizeof(*tcp) > data_end)
        return XDP_PASS;

    __u8 tcp_doff = tcp->doff;
    if (tcp_doff < 5) /* minimum doff is 5 (20 bytes) */
        return XDP_PASS;

    __u32 tcp_header_len = tcp_doff * 4;
    if (data + sizeof(*eth) + ip_header_len + tcp_header_len > data_end)
        return XDP_PASS;

    /* 6. Apply zero-window drop logic for established TCP (ACK set, SYN/RST clear) */
    /* Check ACK flag: tcp->ack is 1 when ACK bit is set */
    if (tcp->ack && !tcp->syn && !tcp->rst) {
        /* Inspect advertised receive window (16-bit, network order) */
        __u16 window = load_u16_be(&tcp->window);
        if (window == 0) {
            /* Drop the packet to mitigate zero-window DoS */
            return XDP_DROP;
        }
    }

    /* 7. Pass all other traffic safely */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
