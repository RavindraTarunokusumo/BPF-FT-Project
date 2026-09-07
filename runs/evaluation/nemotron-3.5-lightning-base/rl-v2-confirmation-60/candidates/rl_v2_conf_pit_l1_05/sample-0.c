#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* 
 * Map definition: 
 * - Type: BPF_MAP_TYPE_ARRAY 
 * - Name: tcp_flags_05 
 * - Key size: 4 bytes (enum index) 
 * - Value size: 8 bytes (__u64) 
 * - Max entries: 8 (covers SYN, ACK, FIN, RST, PSH + padding) 
 */
SEC("xdp")
int xdp_tcp_flags_05(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet frame minimum size */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 protocol */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify IPv4 protocol is TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Verify TCP header bounds */
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* Initialize all counters to zero on first use (optional, ensures clean state) */
    __u64 zero = 0;
    bpf_map_update_elem(bpf_map_fd_tcp_flags_05, &zero, &zero, BPF_ANY);

    /* Inspect TCP flags and increment matching index */
    __u64 idx = 0;
    __u64 *counter;

    if (tcp->syn && !tcp->ack) {
        /* SYN flag set without ACK */
        idx = 0;
    } else if (tcp->ack && !tcp->syn) {
        /* ACK flag set without SYN */
        idx = 1;
    } else if (tcp->fin && !tcp->syn && !tcp->ack) {
        /* FIN flag set */
        idx = 2;
    } else if (tcp->rst) {
        /* RST flag set */
        idx = 3;
    } else if (tcp->psh) {
        /* PSH flag set */
        idx = 4;
    } else {
        /* No matching flag pattern – do not increment */
        return XDP_PASS;
    }

    /* Atomically increment the counter for the matched flag */
    counter = bpf_map_lookup_elem(bpf_map_fd_tcp_flags_05, &idx);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
