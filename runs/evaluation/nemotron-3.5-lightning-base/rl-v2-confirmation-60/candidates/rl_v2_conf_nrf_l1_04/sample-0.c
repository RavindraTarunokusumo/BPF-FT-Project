#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_tcp_port_reversal(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Validate IPv4 header length: ihl is in 32-bit words, multiply by 4 */
    unsigned int ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr) || (void *)(ip + ihl) > data_end)
        return XDP_PASS;

    /* Only process TCP protocol */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Verify TCP header bounds */
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Swap TCP source and destination ports in-place */
    __be16 tmp = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp;

    /* Transmit the modified packet with XDP_TX */
    return XDP_TX;
}

char LICENSE[] = "GPL";
