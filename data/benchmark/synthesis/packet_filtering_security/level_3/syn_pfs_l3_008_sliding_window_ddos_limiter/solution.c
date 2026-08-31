#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define SLOT_DURATION_NS 250000000ULL // 250ms per slot (4 slots = 1 second)
#define MAX_PKTS_PER_SEC 100

struct sliding_window {
    __u64 last_epoch_ns;
    __u32 slot_counts[4];
    __u32 current_slot;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32); // /24 subnet key
    __type(value, struct sliding_window);
    __uint(max_entries, 1024);
} subnet_limiter_map SEC(".maps");

SEC("xdp")
int xdp_sliding_window_limiter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __be32 subnet = ip->saddr & bpf_htonl(0xFFFFFF00); // /24 subnet
    __u64 now = bpf_ktime_get_ns();

    struct sliding_window *win = bpf_map_lookup_elem(&subnet_limiter_map, &subnet);
    if (!win) {
        struct sliding_window new_win = {
            .last_epoch_ns = now,
            .slot_counts = {1, 0, 0, 0},
            .current_slot = 0,
        };
        bpf_map_update_elem(&subnet_limiter_map, &subnet, &new_win, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = now > win->last_epoch_ns ? (now - win->last_epoch_ns) : 0;
    __u32 slots_passed = elapsed / SLOT_DURATION_NS;

    if (slots_passed >= 4) {
        win->slot_counts[0] = 1;
        win->slot_counts[1] = 0;
        win->slot_counts[2] = 0;
        win->slot_counts[3] = 0;
        win->current_slot = 0;
        win->last_epoch_ns = now;
        return XDP_PASS;
    } else if (slots_passed > 0) {
        for (int i = 0; i < 3; i++) {
            if (i < slots_passed) {
                __u32 next_slot = (win->current_slot + i + 1) % 4;
                win->slot_counts[next_slot] = 0;
            }
        }
        win->current_slot = (win->current_slot + slots_passed) % 4;
        win->last_epoch_ns = now;
    }

    __u32 total = win->slot_counts[0] + win->slot_counts[1] + win->slot_counts[2] + win->slot_counts[3];
    if (total >= MAX_PKTS_PER_SEC)
        return XDP_DROP;

    __u32 slot = win->current_slot % 4;
    win->slot_counts[slot] += 1;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
