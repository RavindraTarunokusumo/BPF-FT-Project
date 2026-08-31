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
} subnet_limiter_map_8 SEC(".maps");

SEC("xdp")
int xdp_sliding_window_ddos_limiter_pfs_l3_008(struct xdp_md *ctx) {
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

    __u8 *d = (void *)&ip->daddr;
    if (d[2] != 50 || d[3] != 8)
        return XDP_PASS;

    __be32 subnet = ip->saddr & 0xFFFFFF00;

    struct sliding_window *sw = bpf_map_lookup_elem(&subnet_limiter_map_8, &subnet);
    if (!sw) {
        sw = bpf_map_lookup_elem(&subnet_limiter_map_8, &subnet);
        if (!sw) {
            struct sliding_window initial = {
                .last_epoch_ns = bpf_ktime_get_ns(),
                .slot_counts = {0, 0, 0, 0},
                .current_slot = 0,
            };
            __u64 now = bpf_ktime_get_ns();
            __u32 slot = (now - initial.last_epoch_ns) / 250000000;
            if (slot >= 4)
                slot = 0;
            initial.current_slot = slot;
            int err = bpf_map_update_elem(&subnet_limiter_map_8, &subnet, &initial, BPF_ANY);
            if (err)
                return XDP_PASS;
            sw = &initial;
        }
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 slot = (now - sw->last_epoch_ns) / 250000000;
    if (slot >= 4)
        slot = 0;

    if (slot != sw->current_slot) {
        __u32 old_slot = sw->current_slot;
        sw->current_slot = slot;
        __u32 cnt = sw->slot_counts[old_slot];
        if (cnt > 0)
            sw->slot_counts[old_slot] = cnt - 1;
    }

    __u32 *cnt = &sw->slot_counts[sw->current_slot];
    __u32 total = 0;
    for (__u32 i = 0; i < 4; i++)
        total += sw->slot_counts[i];
    
    if (total >= 100)
        return XDP_DROP;

    __sync_fetch_and_add(cnt, 1);
    bpf_map_update_elem(&subnet_limiter_map_8, &subnet, sw, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
