#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Define the XDP program entry point */
SEC("xdp")
int tcp23_drop_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Check Ethernet bounds and protocol */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS; /* Truncated Ethernet frame */

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS; /* Not IPv4 */

    /* 2. Check IPv4 bounds and protocol */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS; /* Truncated IP header */

    /* 3. Verify IP protocol is TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS; /* Not TCP */

    /* 4. Parse variable IHL safely.
       ip->ihl is in 4-byte words. Multiply by 4 to get byte offset.
       Ensure IHL is at least 5 (minimum header size) and that
       the TCP header fits within the packet bounds. */
    unsigned int ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return XDP_PASS; /* Invalid IHL */

    /* Calculate the start of the TCP payload/header */
    struct tcphdr *tcp = data + sizeof(*eth) + ihl;
    if (data + sizeof(*eth) + ihl + sizeof(*tcp) > data_end)
        return XDP_PASS; /* Truncated TCP header */

    /* 5. Check Destination Port */
    /* TCP header byte order is network (big-endian), matching ip->dport */
    if (tcp->dest == bpf_htons(23)) {
        return XDP_DROP; /* Drop Telnet traffic */
    }

    return XDP_PASS; /* Pass all other traffic */
}

char _license[] SEC("license") = "GPL";
