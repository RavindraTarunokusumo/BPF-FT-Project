/* XDP program: Drop initial IPv4 TCP SYN packets targeting privileged ports (1-1023)
 *
 * This program inspects passing Ethernet frames, verifies they are IPv4 TCP,
 * checks for initial SYN packets (SYN flag set, ACK flag unset), and drops
 * those destined for privileged destination ports (1-1023).
 *
 * Compilation: clang -target bpf -O2 -c xdp_syn_privileged_ports.c -o xdp_syn_privileged_ports.o
 * Load:      ip link set dev <iface> xdp obj xdp_syn_privileged_ports.o sec xdp
 * Unload:    ip link set dev <iface> xdp off
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Helper to safely access the TCP header given an IP packet start.
 * Returns pointer to TCP header or NULL if out of bounds.
 */
static __always_inline struct tcphdr *
tcp_hdr(void *data, void *data_end, struct iphdr *ip)
{
    /* TCP header starts after the IPv4 header.
     * ip->ihl is in 32-bit words; multiply by 4 to get bytes. */
    void *tcp = data + (ip->ihl * 4);

    /* Verify TCP header fits within the packet bounds. */
    if (tcp + sizeof(struct tcphdr) > data_end)
        return NULL;

    return tcp;
}

SEC("xdp")
int xdp_syn_privileged_ports(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Verify we have enough data for an Ethernet header. */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* 2. Verify Ethernet protocol is IPv4 (0x0800). */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify we have enough data for an IPv4 header. */
    if (data + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);

    /* 4. Verify IP protocol is TCP. */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 5. Safely parse TCP header using variable IHL.
     *    ip->ihl is the number of 32-bit words in the IPv4 header. */
    struct tcphdr *tcp = tcp_hdr(data, data_end, ip);
    if (!tcp)
        return XDP_PASS;

    /* 6. Check for initial SYN flag set and ACK flag unset.
     *    TCP flags are at offset 13 from the start of the TCP header.
     *    The check ((flags & 0x12) == 0x02) verifies:
     *      - bit 1 (SYN) is set  -> 0x02
     *      - bit 4 (ACK) is clear -> 0x10 must be 0
     *    Since 0x12 = 0x02 | 0x10, the AND isolates both bits;
     *    result must equal exactly 0x02 (SYN set, ACK clear). */
    __u16 flags = tcp->syn ? 0x02 : 0; /* we will use raw check below */
    /* Direct raw flag inspection as required: */
    if (((tcp->th_flags & 0x12) != 0x02))
        return XDP_PASS;

    /* 7. Check destination port range: 1 <= dport <= 1023.
     *    Network byte order -> convert to host for range check,
     *    or compare after ntohs. */
    __u16 dport = ntohs(tcp->dest);
    if (dport < 1 || dport > 1023)
        return XDP_PASS;

    /* 8. Match all criteria -> drop the packet. */
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
