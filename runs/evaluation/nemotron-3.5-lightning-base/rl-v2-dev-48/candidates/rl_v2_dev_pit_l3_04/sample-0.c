#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* 
 * Array map 'win_dist_04' with 4 bins for window size histogram.
 * Bin 0: win < 4096
 * Bin 1: 4096 <= win < 16384
 * Bin 2: 16384 <= win < 65535
 * Bin 3: win >= 65535
 */
SEC("xdp")
int xdp_win_dist_04(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet frame minimum size */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* Only process IPv4 over TCP */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    void *ip_data = data + sizeof(struct ethhdr);
    struct iphdr *ip;

    /* Verify IPv4 header bounds */
    if (ip_data + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    ip = ip_data;

    /* Only process TCP protocol */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    void *tcp_data = ip_data + (ip->ihl * 4);
    struct tcphdr *tcp;

    /* Verify TCP header bounds */
    if (tcp_data + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    tcp = tcp_data;

    /* Inspect TCP window field (network byte order) */
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
    __sync_fetch_and_add(&win_dist_04[bucket], 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
