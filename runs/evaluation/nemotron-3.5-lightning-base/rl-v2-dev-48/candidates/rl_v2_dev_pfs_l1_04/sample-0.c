/* XDP program: Drop unencrypted remote system log notifications on UDP port 514
 * This program monitors UDP traffic and drops packets sent on UDP port 514,
 * which is the standard port for unencrypted syslog (RFC 5424/3164).
 * All other network traffic is passed through.
 *
 * Compilation: clang -target bpf -O2 -c xdp_drop_port514.c -o xdp_drop_port514.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Helper macro to safely access field within a struct given a data pointer */
#define GET_FIELD(ptr, field) (*(u16 *)((char *)(ptr) + offsetof(struct udphdr, field)))

/* XDP entry point */
SEC("xdp")
int xdp_drop_port514(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Verify IPv4 protocol and header bounds */
    /* Check for IPv4 EtherType (0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct eth_hdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 3. Confirm protocol is IPPROTO_UDP and validate IPv4 header length */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Safely validate variable IPv4 header length: ihl is in 32-bit words */
    u32 ip_hdr_len = (u32)ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > (data_end - (void *)ip))
        return XDP_PASS;

    /* 4. Verify UDP header bounds against data_end */
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* 5. Drop packet with XDP_DROP if UDP destination port equals 514 */
    /* ntohs converts network byte order to host byte order for comparison */
    if (ntohs(udp->dest) == 514)
        return XDP_DROP;

    /* 6. Return XDP_PASS for non-matching or malformed traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
