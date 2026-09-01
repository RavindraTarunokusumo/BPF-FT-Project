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

    unsigned char *ptr = (void *)(eth + 1);
    if (ptr + sizeof(struct mpls_hdr) > data_end)
        return XDP_PASS;

    struct mpls_hdr *mpls = (void *)ptr;
    __u32 bos_label = mpls->label;

    while (1) {
        if (mpls->ttl <= 0)
            break;
        if ((void *)(mpls + 1) > data_end)
            break;
        if (mpls->bos)
            break;
        mpls = (void *)mpls + 1;
    }

    __u32 key = bos_label;
    struct mpls_stats *stats = bpf_map_lookup_elem(&vpn_stats_map, &key);
    if (stats) {
        stats->pkts += 1;
        stats->bytes += ((__u64)data_end - (__u64)data);
    } else {
        struct mpls_stats initial = {1, ((__u64)data_end - (__u64)data)};
        bpf_map_update_elem(&vpn_stats_map, &key, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
