/* XDP program: Drop IPv4 traffic sourced from 198.51.100.0/24,
 * except UDP traffic destined for port 53 (DNS).
 *
 * Author: AI Assistant
 * License: GPL-2.0
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/ctx/sk_buff.h>

/* Helper to safely access the IPv4 header */
static __always_inline struct iphdr *
ip_hdr(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Ensure Ethernet header is present */
    if (data + sizeof(struct ethhdr) > data_end)
        return NULL;

    struct ethhdr *eth = data;
    /* Verify Ethernet protocol is IPv4 (0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return NULL;

    /* Ensure IPv4 header fits within the packet */
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return NULL;

    return (struct iphdr *)(data + sizeof(struct ethhdr));
}

/* Helper to safely access the UDP header after IPv4 */
static __always_inline struct udphdr *
udp_hdr(struct xdp_md *ctx)
{
    struct iphdr *ip = ip_hdr(ctx);
    if (!ip)
        return NULL;

    /* Verify IP protocol is UDP */
    if (ip->protocol != IPPROTO_UDP)
        return NULL;

    /* Calculate UDP header start */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *udp = (void *)(ip + 1);

    /* UDP header must be within bounds */
    if (udp + sizeof(struct udphdr) > data_end)
        return NULL;

    return udp;
}

SEC("xdp")
int xdp_l2_source_subnet_exception(struct xdp_md *ctx)
{
    struct iphdr *ip = ip_hdr(ctx);
    if (!ip)
        /* Non-IPv4 or malformed packet: pass through */
        return XDP_PASS;

    /* Check source address subnet: 198.51.100.0/24 (0xC6336400) */
    __u32 saddr = bpf_ntohl(ip->saddr);
    if ((saddr & 0xFFFFFF00) == 0xC6336400) {
        /* Source is within the target subnet */
        struct udphdr *udp = udp_hdr(ctx);
        if (udp && ip->protocol == IPPROTO_UDP &&
            bpf_ntohs(udp->dest) == 53) {
            /* Exception: UDP dest port 53 (DNS) -> pass */
            return XDP_PASS;
        }
        /* All other traffic from this subnet -> drop */
        return XDP_DROP;
    }

    /* Non-matching subnet -> pass */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
