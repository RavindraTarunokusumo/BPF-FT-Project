/* XDP program: rl_v2_conf_nrf_l1_03
 * Category: network_routing_forwarding
 * Difficulty: level_1
 * 
 * Description:
 *   Turns around inbound TCP packets by transposing Layer 4 port endpoints.
 *   All other packets are passed through with XDP_PASS.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Helper macro to safely access packet data within bounds */
static __always_inline void *ptr_load(volatile void *addr, int size)
{
    return bpf_probe_read(addr, size);
}

SEC("xdp")
int xdp_port_transpose(struct xdp_md *ctx)
{
    void *data_end;
    void *data;

    /* Retrieve packet data pointers from context */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* 1. Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Confirm Ethernet type is IPv4 (ETH_P_IP) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify IPv4 header bounds and extract IPv4 header */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 4. Confirm IP protocol is TCP (IPPROTO_TCP) */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 5. Safely validate variable IPv4 header length (ihl * 4) */
    /* ihl is in 4-byte units; ensure it is at least 5 (20 bytes minimum) */
    if (ip->ihl < 5)
        return XDP_PASS;

    /* Calculate IPv4 header end bound */
    void *ip_end = (void *)ip + (ip->ihl * 4);
    if (ip_end > data_end)
        return XDP_PASS;

    /* 6. Verify TCP header bounds */
    struct tcphdr *tcp = (struct tcphdr *)ip_end;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* 7. Transpose Layer 4 port endpoints in-place */
    __be16 tmp = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp;

    /* 8. Return XDP_TX for reflected packets */
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
