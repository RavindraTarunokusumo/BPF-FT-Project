#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/ctx.h>
#include <bpf/eth.h>

/* 
 * 4-way ECMP router XDP program
 * Hashes IPv4 5-tuple and redirects to one of 4 next-hops
 * Non-IP traffic is passed through
 */

SEC("xdp")
int xdp_ecmp_router(struct bpf_xdp_ctx *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    __u16 proto;
    __u32 hash = 0;

    /* Verify we have enough data for Ethernet header */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Only process IPv4 */
    proto = eth->h_proto;
    if (proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify we have enough data for IPv4 header */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);

    /* Verify IPv4 version */
    if (ip->version != 4)
        return XDP_PASS;

    /* 
     * Extract 5-tuple: 
     * Source IP, Dest IP, Source Port, Dest Port, Protocol
     * We use only the transport portion if present, 
     * otherwise fall back to IP fields
     */
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        /* TCP/UDP: need transport header after IP header */
        void *transport = data + sizeof(*eth) + ip->ihl * 4;
        
        if (transport + (ip->protocol == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr)) > data_end)
            return XDP_PASS;

        /* Compute hash using IP addresses and ports */
        /* Simple but effective: mix all 5-tuple components */
        hash ^= *(__u32 *)(data + sizeof(*eth) + 12);   /* src ip */
        hash ^= *(__u32 *)(data + sizeof(*eth) + 16);   /* dst ip */
        
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = transport;
            hash ^= *(__u16 *)(&udp->source);
            hash ^= *(__u16 *)(&udp->dest);
        } else {
            struct tcphdr *tcp = transport;
            hash ^= *(__u16 *)(&tcp->source);
            hash ^= *(__u16 *)(&tcp->dest);
        }
    } else {
        /* ICMP or other IP protocols: hash on IPs and protocol */
        hash ^= *(__u32 *)(data + sizeof(*eth) + 12);   /* src ip */
        hash ^= *(__u32 *)(data + sizeof(*eth) + 16);   /* dst ip */
        hash ^= (__u32)ip->protocol;
    }

    /* 4-way ECMP: redirect to ifindex 10, 11, 12, or 13 */
    hash = hash % 4;
    __u32 ifindex = 10 + hash;

    /* Redirect packet to selected next-hop */
    bpf_xdp_redirect_index(ctx, ifindex, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
