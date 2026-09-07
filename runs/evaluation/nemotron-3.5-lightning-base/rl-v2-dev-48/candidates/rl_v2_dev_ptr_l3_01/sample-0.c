#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

/* XDP program entry point */
SEC("xdp")
int xdp_decapsulate_6in4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify outer IPv4 header bounds */
    struct iphdr *outer_ip = (struct iphdr *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    /* Check if outer protocol is IP-in-IP (protocol 41) */
    if (outer_ip->protocol != IPPROTO_IPV6)
        return XDP_PASS;

    /* Calculate variable outer IPv4 header length */
    int outer_len = outer_ip->ihl * 4;

    /* Verify that the stripped payload fits within the packet buffer */
    if ((void *)(eth + 1 + outer_len) > data_end)
        return XDP_PASS;

    /* Back up the original Ethernet header */
    struct eth_hdr saved_eth = *eth;

    /* Update Ethernet protocol to ETH_P_IPV6 (0x86DD) */
    eth->h_proto = htons(ETH_P_IPV6);

    /* Adjust the packet head to strip the outer IPv4 header */
    int ret = bpf_xdp_adjust_head(ctx, outer_len);
    if (ret)
        return ret;

    /* Restore the updated Ethernet header after adjustment */
    *eth = saved_eth;

    /* Forward the packet unconditionally */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
