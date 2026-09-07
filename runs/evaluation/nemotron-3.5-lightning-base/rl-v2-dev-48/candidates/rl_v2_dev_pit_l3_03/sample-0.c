#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* 
 * Map to store TCP receiver window size distribution.
 * 4 bins:
 *   Bin 0: win < 4096
 *   Bin 1: 4096 <= win < 16384
 *   Bin 2: 16384 <= win < 65535
 *   Bin 3: win >= 65535
 */
SEC("xdp")
int xdp_win_dist_03(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet frame minimum size */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* Verify IPv4 protocol */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Point to IPv4 header after Ethernet header */
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Verify IPv4 IHL and total length */
    if (ip->ihl < 5 || ip->ihl * 4 > (size_t)(data_end - (void *)ip))
        return XDP_PASS;

    /* Verify TCP protocol */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Point to TCP header after IPv4 header */
    int ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Verify TCP header minimum size (20 bytes) */
    if (tcp->doff < 5)
        return XDP_PASS;

    /* Point to end of TCP header using data_offset field */
    void *tcp_end = (void *)tcp + (tcp->doff * 4);
    if (tcp_end > data_end)
        return XDP_PASS;

    /* Inspect TCP receiver window (network byte order -> host byte order) */
    __u16 win = bpf_ntohs(tcp->window);

    /* Select bucket based on window size */
    int bucket;
    if (win < 4096)
        bucket = 0;
    else if (win < 16384)
        bucket = 1;
    else if (win < 65535)
        bucket = 2;
    else
        bucket = 3;

    /* Atomically increment the selected bucket counter */
    __sync_fetch_and_add(&win_dist_03[bucket], 1);

    return XDP_PASS;
}

char LICENSE[] = "GPL";
