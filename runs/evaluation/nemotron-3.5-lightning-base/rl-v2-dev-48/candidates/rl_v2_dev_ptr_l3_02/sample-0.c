#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

/* XDP program entry point */
SEC("xdp")
int xdp_unwrap_ipv6_in_ipv4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify outer IPv4 header bounds */
    /* outer_ip points to the start of the outer IPv4 header immediately after the Ethernet header */
    struct iphdr *outer_ip = (struct iphdr *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    /* Check if the outer protocol is IPv4 (protocol 41 = IPPROTO_IPV6 in the outer header field) */
    if (outer_ip->protocol != 41)
        return XDP_PASS;

    /* Calculate the outer IPv4 header length in bytes */
    __u32 outer_len = outer_ip->ihl * 4;

    /* Back up the original Ethernet header for restoration after adjustment */
    struct ethhdr saved_eth;
    bpf_memcpy(&saved_eth, eth, sizeof(saved_eth), BPF_F_CTX);

    /* Update the Ethernet protocol type to ETH_P_IPV6 (0x86DD) */
    eth->h_proto = htons(ETH_P_IPV6);

    /* Adjust the packet head by the outer IPv4 header length.
     * This effectively removes the outer IPv4 header, revealing the inner IPv6 packet. */
    int ret = bpf_xdp_adjust_head(ctx, outer_len);
    if (ret)
        return XDP_PASS; /* adjustment failed, pass original packet */

    /* Restore the updated Ethernet header that was modified before adjust_head.
     * adjust_head moves the data pointer, so we must write back to the new location. */
    bpf_memcpy(eth, &saved_eth, sizeof(saved_eth), BPF_F_CTX);

    /* Unconditionally pass the transformed packet */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
