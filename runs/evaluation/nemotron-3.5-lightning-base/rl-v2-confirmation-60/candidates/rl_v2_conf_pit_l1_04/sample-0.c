#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* Map: tcp_flags_04
 * Type: BPF_MAP_TYPE_ARRAY
 * Key: __u32 (index 0..4)
 * Value: __u64 (64-bit counter)
 * Max entries: 8 (indices 0..7, only 0..4 used)
 */
SEC("xdp")
int xdp_tcp_flags_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 protocol */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    void *ip_data = data + sizeof(*eth);
    struct iphdr *ip = ip_data;
    if (ip_data + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify IPv4 and TCP protocol */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    void *tcp_data = ip_data + (ip->ihl * 4);
    struct tcphdr *tcp = tcp_data;
    if (tcp_data + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* Extract TCP flags */
    __u16 flags = tcp->rst | (tcp->syn << 1) | (tcp->fin << 2) | (tcp->psh << 3) | (tcp->ack << 4);

    /* Map to index and increment counter atomically */
    if (flags & (1 << 0)) { /* SYN */
        __sync_fetch_and_add((__u64 *)bpf_map_lookup_elem(&tcp_flags_04, &(__u32){0}), 1);
    } else if (flags & (1 << 1)) { /* ACK */
        __sync_fetch_and_add((__u64 *)bpf_map_lookup_elem(&tcp_flags_04, &(__u32){1}), 1);
    } else if (flags & (1 << 2)) { /* FIN */
        __sync_fetch_and_add((__u64 *)bpf_map_lookup_elem(&tcp_flags_04, &(__u32){2}), 1);
    } else if (flags & (1 << 3)) { /* RST */
        __sync_fetch_and_add((__u64 *)bpf_map_lookup_elem(&tcp_flags_04, &(__u32){3}), 1);
    } else if (flags & (1 << 4)) { /* PSH */
        __sync_fetch_and_add((__u64 *)bpf_map_lookup_elem(&tcp_flags_04, &(__u32){4}), 1);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
