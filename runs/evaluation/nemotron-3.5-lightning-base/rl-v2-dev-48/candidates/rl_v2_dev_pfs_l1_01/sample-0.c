#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_tftp_block(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

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
    if (ihl < sizeof(struct iphdr) || (void *)(ip + ihl) > data_end)
        return XDP_PASS;

    /* Verify UDP header bounds */
    struct udphdr *udp = (struct udphdr *)(ip + ihl);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Drop packet with UDP destination port equals 69 (TFTP) */
    if (udp->dest == htons(69))
        return XDP_DROP;

    /* Return XDP_PASS for non-matching or malformed traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
