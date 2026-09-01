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
int xdp_syn_pfs_l3_008_sliding_window_ddos_limiter(struct xdp_md *ctx) {
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

    __be32 src_ip = ip->saddr;
    __u8 *p = (void *)&src_ip;
    __u32 subnet = (p[0] & 0xFF) << 16 | (p[1] & 0xFF) << 8 | (p[2] & 0xFF);

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
    __u32 elapsed = (now - sw->last_epoch_ns) / 250000000;

    if (elapsed > 0) {
        __u32 old_slot = sw->current_slot;
        sw->current_slot = (old_slot + elapsed) % 4;
        for (__u32 i = 0; i < elapsed; i++) {
            __u32 slot = (old_slot + i) % 4;
            sw->slot_counts[slot] = 0;
        }
    }

    __u32 slot = sw->current_slot;
    if (sw->slot_counts[slot] < 100) {
        sw->slot_counts[slot]++;
        bpf_map_update_elem(&subnet_limiter_map, &subnet, sw, BPF_ANY);
        return XDP_PASS;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
