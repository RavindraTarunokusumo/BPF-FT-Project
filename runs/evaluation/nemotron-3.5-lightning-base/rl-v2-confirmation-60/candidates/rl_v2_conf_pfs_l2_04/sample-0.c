#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_drop_zero_window(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Verify IPv4 header and confirm protocol is IPPROTO_TCP */
    /* Check EtherType == htons(ETH_P_IP) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Confirm protocol is IPPROTO_TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 4. Safely validate variable IPv4 header length (ip->ihl * 4) */
    /* ihl is in 32-bit words; minimum is 5 (20 bytes) */
    unsigned int ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr) || data + sizeof(*eth) + ihl > data_end)
        return XDP_PASS;

    /* 5. Verify TCP header bounds against data_end */
    struct tcphdr *tcp = data + sizeof(*eth) + ihl;
    if (data + sizeof(*eth) + ihl + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* 6. Drop packet with XDP_DROP if tcp->window equals 0 */
    if (tcp->window == 0)
        return XDP_DROP;

    /* 7. Return XDP_PASS for non-matching or malformed traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
