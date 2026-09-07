#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/ip.h>
#include <bpf/ctx/skb.h>

/* XDP program entry point */
SEC("xdp")
int xdp_fragment_filter(struct xdp_md *ctx)
{
    void *data_end;
    void *data;
    struct eth_hdr *eth;
    struct iphdr *ip;

    /* Obtain packet data pointers from the XDP context */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Only process IPv4 traffic (ETH_P_IP = 0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Adjust pointer to IPv4 header, verify bounds */
    ip = (void *)(eth + 1);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Check fragmentation flags and offset.
     * frag_off is network byte order.
     * IP_MF flag is bit 13 (0x2000).
     * Fragment offset mask is 0x1FFF (13 bits).
     * Combined check: (ntohs(frag_off) & 0x3FFF) != 0
     *   - 0x3FFF = 0x2000 (MF) | 0x1FFF (offset mask)
     *   - If non-zero, packet is a fragment or final fragment. */
    if (bpf_ntohs(ip->frag_off) & 0x3FFF)
        return XDP_DROP;

    /* Non-fragmented IPv4 packet: pass through */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
