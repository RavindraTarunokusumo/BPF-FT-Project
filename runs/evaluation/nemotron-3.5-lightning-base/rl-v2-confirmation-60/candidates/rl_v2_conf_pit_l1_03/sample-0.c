#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* 
 * Map name: tcp_flags_03 
 * Type: BPF_MAP_TYPE_ARRAY 
 * Key type: int (u32) 
 * Value type: u64 
 * Max entries: 8 
 */
SEC("xdp")
int xtcp_flag_profiler(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet frame presence */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 presence and bounds */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify IPv4 protocol is TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Verify TCP header presence and bounds */
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* 
     * TCP flags inspection and atomic increment.
     * Map index mapping: SYN->0, ACK->1, FIN->2, RST->3, PSH->4
     * Unmatched flags leave the counter at index 0 (no-op increment).
     */
    int idx = 0; /* default index for unmatched or zero flags */

    if (tcp->syn && !tcp->ack)
        idx = 0; /* SYN */
    else if (tcp->ack && !tcp->syn)
        idx = 1; /* ACK */
    else if (tcp->fin && !tcp->syn && !tcp->ack)
        idx = 2; /* FIN */
    else if (tcp->rst)
        idx = 3; /* RST */
    else if (tcp->psh)
        idx = 4; /* PSH */

    /* Atomically increment the corresponding counter */
    __sync_fetch_and_add((unsigned long *)bpf_map_lookup_elem(
                             &tcp_flags_03, &idx), 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
