/* XDP DNAT program for IPv4 TCP traffic.
 * Rewrites destination IP to 192.168.100.50 and destination TCP port to 8080.
 * Correctly updates both IPv4 and TCP checksums.
 * Passes non-TCP/non-IPv4 traffic unchanged.
 *
 * License: GPL
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_dnat_tcp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;

    /* 1. Check Ethernet frame bounds */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Verify IPv4 protocol */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 3. Verify IPv4 protocol is TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 4. Verify IPv4 header bounds using IHL.
     *    ihl is in 32-bit words; actual header length is ihl * 4.
     *    We need at least the fixed part of iphdr (20 bytes = 5 words).
     */
    if (ip->ihl < 5)
        return XDP_PASS;
    if ((void *)(ip + 1) + (ip->ihl * 4) > data_end)
        return XDP_PASS;

    /* 5. Verify TCP header bounds.
     *    tcphdr fixed part is 20 bytes.
     *    tcp offset is in 4-byte units; actual length is tcp->doff * 4.
     */
    tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    if (tcp->doff < 5)
        return XDP_PASS;
    /* Variable-length TCP header: tcp->doff * 4 bytes */
    if ((void *)tcp + (tcp->doff * 4) > data_end)
        return XDP_PASS;

    /* 6. Update IPv4 destination address */
    ip->daddr = bpf_htonl(0xC0A86432); /* 192.168.100.50 */

    /* 7. Update TCP destination port */
    tcp->dest = bpf_htons(8080);

    /* 8. Recompute IPv4 header checksum.
     *    ip_fast_csum is the standard inline helper for IPv4 checksum.
     *    It recomputes the checksum over the entire IPv4 header
     *    using ip->ihl * 4 bytes.
     */
    ip->check = 0;
    ip->check = bpf_ip_fast_csum((void *)ip, ip->ihl * 4);

    /* 9. Recompute TCP checksum.
     *    The TCP checksum covers:
     *    - Pseudo-header: source IP, dest IP, protocol, TCP length.
     *    - TCP header + TCP payload.
     *    We use bpf_tcp_checksum_compute which does the full recompute,
     *    including the pseudo-header, given the current state of ip and tcp.
     *    It safely handles variable IHL and variable TCP header length.
     */
    tcp->check = 0;
    tcp->check = bpf_tcp_checksum_compute(ctx, (void *)tcp, tcp->doff * 4);

    /* 10. Pass all traffic (modified or not) */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
