#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

SEC("xdp")
int xdp_filter_syn_pfs_l3_008_sliding_window_ddos_limiter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __be32 subnet = ip->saddr & bpf_htons(0xFFFFFF00);

    struct sliding_window *sw = bpf_map_lookup_elem(&subnet_limiter_map, &subnet);
    if (!sw) {
        struct sliding_window initial = {
            .last_epoch_ns = bpf_ktime_get_ns(),
            .slot_counts = {0, 0, 0, 0},
            .current_slot = 0,
        };
        bpf_map_update_elem(&subnet_limiter_map, &subnet, &initial, BPF_ANY);
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - sw->last_epoch_ns;

    if (elapsed >= 250000000ULL) {
        __u32 slot_duration = 250000000ULL;
        __u32 num_slots = elapsed / slot_duration;
        if (num_slots > 4)
            num_slots = 4;

        for (__u32 i = 0; i < num_slots; i++) {
            sw->slot_counts[sw->current_slot] = 0;
            sw->current_slot = (sw->current_slot + 1) % 4;
        }
        sw->last_epoch_ns = now;
    }

    __u32 total = 0;
    for (int i = 0; i < 4; i++)
        total += sw->slot_counts[i];

    if (total >= 100)
        return XDP_DROP;

    sw->slot_counts[sw->current_slot]++;
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
