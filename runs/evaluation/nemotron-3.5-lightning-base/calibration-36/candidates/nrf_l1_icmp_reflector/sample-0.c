/* nrf_l1_icmp_reflector
 *
 * XDP program that reflects valid IPv4 ICMP packets at Layer 2
 * by swapping Ethernet source and destination MAC addresses
 * and returning XDP_TX. All other traffic is passed unchanged.
 *
 * GPL License
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>

/* Helper to safely access packet data within bounds */
static __always_inline void *data_ptr(void *data, void *data_end, __u64 offset)
{
    void *ptr = data + offset;
    if (ptr > data_end)
        return NULL;
    return ptr;
}

SEC("xdp")
int nrf_l1_icmp_reflector(struct xdp_md *ctx)
{
    void *data_end;
    void *data;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct icmphdr *icmp;

    /* Obtain packet boundaries */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet frame bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Verify Ethernet type is IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);

    /* Verify IPv4 protocol is ICMP */
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    /* Verify ICMP header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) > data_end)
        return XDP_PASS;

    icmp = data + sizeof(*eth) + sizeof(*ip);

    /* Swap Ethernet source and destination MAC addresses */
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source_orig, ETH_ALEN); /* placeholder */

    /* Correct swap using temporary storage */
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);

    /* Reflect the packet by returning XDP_TX */
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
