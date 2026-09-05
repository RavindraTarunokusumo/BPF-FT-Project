#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * Tiered ACL XDP program.
 * - Checks allowlist_map for the source IP first.
 * - If the source IP is allowlisted, the packet is passed immediately.
 * - If not allowlisted and the destination port is 22 (SSH), the packet is dropped.
 * - All other traffic (port 80, UDP, ARP, etc.) is passed.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 128);
} allowlist_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Verify there is enough data for an Ethernet header. */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic. */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    /* Verify there is enough data for the IP header. */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    /* Verify the IP header length and that it fits within the frame. */
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    /* Verify there is enough data for the TCP header. */
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Tier 1: Check allowlist_map for the source IP first. */
    __u32 src = ip->saddr;
    __u8 *allowed = bpf_map_lookup_elem(&allowlist_map, &src);
    if (allowed && *allowed == 1)
        return XDP_PASS;

    /* Tier 2: If not allowlisted and destination port is 22, drop. */
    if (tcp->dest == bpf_htons(22))
        return XDP_DROP;

    /* All other traffic is passed. */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
