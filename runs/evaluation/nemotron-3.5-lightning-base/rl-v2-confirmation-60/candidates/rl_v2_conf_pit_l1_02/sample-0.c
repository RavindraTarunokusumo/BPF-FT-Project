#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Map to store 8 counters for TCP flag frequencies.
 * Index mapping: SYN->0, ACK->1, FIN->2, RST->3, PSH->4.
 * Remaining indices (5-7) are reserved/unused but reserved for map size. */
SEC("xdp")
int xdp_tcp_flags_02(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;

    /* Verify Ethernet frame boundary */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Verify IPv4 payload boundary */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);

    /* Only process IPv4 packets */
    if (ip->version != 4)
        return XDP_PASS;

    /* Verify TCP payload boundary */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    tcp = data + sizeof(*eth) + sizeof(*ip);

    /* Only process TCP packets */
    if (tcp->source == 0 && tcp->dest == 0)
        return XDP_PASS; /* simplified check; real apps use ports */

    /* Atomically increment the matching counter based on TCP flags.
     * Flags are checked in the specified priority order. */
    if (tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh)
        __sync_fetch_and_add(&tcp_flags_2[0], 1); /* SYN -> index 0 */
    else if (!tcp->syn && tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh)
        __sync_fetch_and_add(&tcp_flags_2[1], 1); /* ACK -> index 1 */
    else if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && tcp->psh)
        __sync_fetch_and_add(&tcp_flags_2[4], 1); /* PSH -> index 4 */
    else if (!tcp->syn && !tcp->ack && !tcp->fin && tcp->rst && !tcp->psh)
        __sync_fetch_and_add(&tcp_flags_2[3], 1); /* RST -> index 3 */
    else if (!tcp->syn && !tcp->ack && tcp->fin && !tcp->rst && !tcp->psh)
        __sync_fetch_and_add(&tcp_flags_2[2], 1); /* FIN -> index 2 */

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
