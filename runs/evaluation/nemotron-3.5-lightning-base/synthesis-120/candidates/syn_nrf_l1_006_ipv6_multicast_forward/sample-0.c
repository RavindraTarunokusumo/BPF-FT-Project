#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>

/* XDP program entry point */
SEC("xdp")
int xdp_multicast_redirect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Validate Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify EtherType == IPv6 (0x86DD) */
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    /* Validate IPv6 header bounds */
    struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    /* Check if destination address starts with ff02::/16 */
    /* First 16 bits of daddr must equal 0xFF02 */
    if (ip6->daddr.s6_addr16[0] == bpf_htons(0xFF02)) {
        /* Redirect to interface with ifindex 4 */
        return bpf_redirect(4, 0);
    }

    /* Pass unicast IPv6 traffic and other protocols */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
