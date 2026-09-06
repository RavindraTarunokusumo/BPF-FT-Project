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

struct mpls_stats {
    __u64 pkts;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct mpls_stats);
} vpn_stats_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_008_mpls_vpn_flow_stats(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    struct mpls_hdr *mpls = (void *)(eth + 1);
    if ((void *)(mpls + 1) > data_end)
        return XDP_PASS;

    __u32 vpn_label = 0;
    while ((void *)(mpls + 1) <= data_end) {
        if (mpls->label == bpf_htons(0x0000))
            break;
        if (mpls->bos) {
            vpn_label = mpls->label;
            break;
        }
        mpls++;
    }

    if (vpn_label) {
        struct mpls_stats *stats = bpf_map_lookup_elem(&vpn_stats_map, &vpn_label);
        if (stats) {
            __sync_fetch_and_add(&stats->pkts, 1);
            __sync_fetch_and_add(&stats->bytes, (__u64)data_end - (__u64)data);
        } else {
            struct mpls_stats initial = {
                .pkts = 1,
                .bytes = (__u64)data_end - (__u64)data,
            };
            bpf_map_update_elem(&vpn_stats_map, &vpn_label, &initial, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
