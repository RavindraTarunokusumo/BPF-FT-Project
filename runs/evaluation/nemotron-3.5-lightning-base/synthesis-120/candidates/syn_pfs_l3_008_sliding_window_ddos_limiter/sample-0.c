#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 
 * Sliding window state per /24 IPv4 subnet.
 * last_epoch_ns: timestamp of the last slot advancement (ns).
 * slot_counts[4]: counter for each 250ms slot.
 * current_slot: index of the active slot (0..3).
 */
struct sliding_window {
    __u64 last_epoch_ns;
    __u32 slot_counts[4];
    __u32 current_slot;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct sliding_window);
} subnet_limiter_map SEC(".maps");

/* 
 * Helper: advance sliding window slots based on elapsed time.
 * Returns the number of slots advanced (0..4).
 */
static __always_inline int advance_slots(struct sliding_window *sw)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ns = now - sw->last_epoch_ns;
    __u32 slots_to_advance = elapsed_ns / 250000000ULL; /* 250ms = 250,000,000 ns */
    __u32 i;

    if (slots_to_advance == 0)
        return 0;
    if (slots_to_advance > 4)
        slots_to_advance = 4;

    /* Zero out the slots being advanced past */
    for (i = 0; i < slots_to_advance; i++)
        sw->slot_counts[i] = 0;

    /* Shift remaining counts forward */
    if (slots_to_advance < 4) {
        __u32 j;
        for (i = slots_to_advance; i < 4; i++) {
            sw->slot_counts[i - slots_to_advance] = sw->slot_counts[i];
            sw->slot_counts[i] = 0;
        }
    }

    sw->current_slot = (sw->current_slot + slots_to_advance) & 3;
    sw->last_epoch_ns = now;
    return slots_to_advance;
}

SEC("xdp")
int xdp_syn_pfs_l3_008_sliding_window_ddos_limiter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Parse Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IPv4 header */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process TCP (to target SYN packets as implied by task name) */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Extract source IP and derive /24 subnet key */
    __be32 src_ip = ip->saddr;
    __be32 subnet = src_ip & bpf_htonl(0xFFFFFF00); /* clear last octet */

    /* Lookup or create sliding window state */
    struct sliding_window *sw = bpf_map_lookup_elem(&subnet_limiter_map, &subnet);
    if (!sw) {
        /* First packet for this subnet: initialize state */
        struct sliding_window init = {
            .last_epoch_ns = bpf_ktime_get_ns(),
            .slot_counts = {0, 0, 0, 0},
            .current_slot = 0,
        };
        sw = bpf_map_update_elem(&subnet_limiter_map, &subnet, &init, BPF_ANY);
        if (!sw)
            return XDP_PASS; /* map update failed, pass packet */
    }

    /* Advance slots if enough time has passed */
    advance_slots(sw);

    /* Increment the count for the current slot */
    sw->slot_counts[sw->current_slot]++;

    /* Sum counts across all 4 slots */
    __u32 total_count = 0;
    int i;
    for (i = 0; i < 4; i++)
        total_count += sw->slot_counts[i];

    /* Drop if total rate >= 100 packets/second */
    if (total_count >= 100) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
