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
} vpn_stats_map_8 SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_008_mpls_vpn_flow_stats(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    unsigned char *p = (void *)(eth + 1);
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 vpn_label = 0;
    while (p < data_end) {
        __u32 label = (__u32)p[0] << 16 | (__u32)p[1] << 8 | (__u32)p[2];
        if (p[3] & 0x01)
            vpn_label = label;
        p += 3;
        if (p < data_end && p[0] == 0x8847)
            continue;
        break;
    }

    if (!vpn_label)
        return XDP_PASS;

    struct mpls_stats *stats = bpf_map_lookup_elem(&vpn_stats_map_8, &vpn_label);
    if (stats) {
        __u64 pkt = (__u64)stats->pkts + 1;
        __u64 byte = (__u64)stats->bytes + (__u64)data_end - (__u64)data;
        stats->pkts = pkt;
        stats->bytes = byte;
    } else {
        struct mpls_stats initial = {
            .pkts = 1,
            .bytes = (__u64)data_end - (__u64)data,
        };
        bpf_map_update_elem(&vpn_stats_map_8, &vpn_label, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
