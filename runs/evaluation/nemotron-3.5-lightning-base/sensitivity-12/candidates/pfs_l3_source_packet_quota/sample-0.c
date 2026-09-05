/* XDP program: per-source IPv4 packet quota enforcement
 *
 * Limits the number of packets processed from a single source IPv4 address.
 * - First packet from a source: inserts count=1, returns XDP_PASS
 * - Subsequent packets: increments count; if count <= 5, XDP_PASS; else XDP_DROP
 * - Non-IPv4 traffic is always passed
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Define the BPF hash map for source IP tracking.
 * Key: __u32 (source IPv4 address)
 * Value: __u64 (packet counter)
 * Max entries: 10240
 */
SEC(".maps")
struct bpf_map source_quota_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 10240,
};

SEC("xdp")
int xdp_source_quota(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify we have enough data for an Ethernet header */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* Only process IPv4 traffic (ETH_P_IP = 0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify we have enough data for an IPv4 header after Ethernet */
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);

    /* Only process IPv4 version 4 (ihl may vary, but we treat fixed header) */
    if (ip->version != 4)
        return XDP_PASS;

    __u32 saddr = ip->saddr;

    /* Look up existing quota count for this source IP */
    __u64 *val = bpf_map_lookup_elem(&source_quota_map, &saddr);

    if (val) {
        /* Existing source: increment quota */
        (*val) += 1;

        /* Allow if count <= 5, drop if over limit */
        if (*val <= 5)
            return XDP_PASS;
        else
            return XDP_DROP;
    }

    /* First packet from this source: insert with count = 1 */
    __u64 init_val = 1;
    if (bpf_map_update_elem(&source_quota_map, &saddr, &init_val, BPF_ANY))
        return XDP_PASS; /* map update failed, allow the packet */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
