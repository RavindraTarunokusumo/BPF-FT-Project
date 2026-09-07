#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Map definition: tcp_flags_01, BPF_MAP_TYPE_ARRAY, 8 entries, __u64 values */
SEC("xdp")
int xdp_tcp_flag_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet frame */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 payload */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify TCP protocol and extract TCP header */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* Inspect TCP control flags and increment matching counter */
    __u64 idx = 0; /* default: no match, index 0 holds non-matching or zero */

    if (tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh)
        idx = 0; /* SYN */
    else if (!tcp->syn && tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh)
        idx = 1; /* ACK */
    else if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh)
        idx = 2; /* FIN */
    else if (!tcp->syn && !tcp->ack && tcp->fin && !tcp->rst && !tcp->psh)
        idx = 2; /* FIN (redundant but explicit) */
    else if (!tcp->syn && !tcp->ack && !tcp->fin && tcp->rst && !tcp->psh)
        idx = 3; /* RST */
    else if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && tcp->psh)
        idx = 4; /* PSH */
    else
        idx = 0; /* other flags or combination – use index 0 */

    /* Atomically increment the counter for the matched flag index */
    __sync_fetch_and_add(&tcp_flags_01[idx], 1);

    return XDP_PASS;
}

char LICENSE[] = "GPL";
SEC("xdp")
int xdp_tcp_flag_counter(struct xdp_md *ctx)
{
    return xdp_tcp_flag_counter(ctx);
}
