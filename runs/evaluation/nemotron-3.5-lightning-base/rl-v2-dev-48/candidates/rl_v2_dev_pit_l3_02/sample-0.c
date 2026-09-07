#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* 
 * XDP program to tabulate flow window buffer metrics.
 * Maps window size distribution into 4 buckets:
 *   Bin 0: win < 4096
 *   Bin 1: 4096 <= win < 16384
 *   Bin 2: 16384 <= win < 65535
 *   Bin 3: win >= 65535
 */
SEC("xdp")
int xdp_win_dist_02(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process TCP segments */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Verify TCP header bounds */
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* 
     * Inspect TCP window field.
     * bpf_ntohs converts network-order window to host byte order.
     * Select bucket based on window size thresholds.
     */
    __u16 win = bpf_ntohs(tcp->window);

    __u32 idx;
    if (win < 4096)
        idx = 0;
    else if (win < 16384)
        idx = 1;
    else if (win < 65535)
        idx = 2;
    else
        idx = 3;

    /* Atomically increment the window bucket counter. */
    __sync_fetch_and_add(&win_dist_02[idx], 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
