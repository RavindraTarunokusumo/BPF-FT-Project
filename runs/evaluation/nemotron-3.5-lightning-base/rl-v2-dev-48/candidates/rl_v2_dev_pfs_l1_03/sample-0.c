/* XDP program: Drop unauthorized SNMP queries over UDP port 161
 *
 * This program monitors UDP traffic and drops SNMP management agent queries
 * arriving over UDP port 161. All other network traffic is passed through.
 *
 * Compilation: clang -target bpf -O2 -c snmp_filter.c -o snpf.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/ctx/sk_buff.h>

SEC("xdp")
int snmp_filter_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify IPv4 protocol and header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Confirm protocol is IPPROTO_UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Safely validate variable IPv4 header length */
    unsigned int ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr) || (void *)(ip + 1) + ihl > data_end)
        return XDP_PASS;

    /* Point to UDP header after IPv4 header */
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Drop packet with XDP_DROP if UDP destination port equals 161 */
    if (udp->dest == htons(161))
        return XDP_DROP;

    /* Return XDP_PASS for non-matching or malformed traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
