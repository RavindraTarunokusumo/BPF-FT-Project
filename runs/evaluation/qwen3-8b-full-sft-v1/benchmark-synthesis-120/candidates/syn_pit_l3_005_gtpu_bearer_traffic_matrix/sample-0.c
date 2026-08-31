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


struct bearer_stats {
    __u64 uplink_bytes;
    __u64 downlink_bytes;
    __u64 total_pkts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct bearer_stats);
} bearer_matrix_map_5 SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_005_gtpu_bearer_matrix(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(2152)) { // Uplink
        __u32 teid = udp->source;
        struct bearer_stats *stats = bpf_map_lookup_elem(&bearer_matrix_map_5, &teid);
        if (stats) {
            stats->uplink_bytes += ctx->data_end - ctx->data;
            stats->total_pkts += 1;
        } else {
            struct bearer_stats initial = {
                .uplink_bytes = ctx->data_end - ctx->data,
                .downlink_bytes = 0,
                .total_pkts = 1,
            };
            bpf_map_update_elem(&bearer_matrix_map_5, &teid, &initial, BPF_ANY);
        }
        return XDP_PASS;
    }

    if (udp->source == bpf_htons(2152)) { // Downlink
        __u32 teid = udp->dest;
        struct bearer_stats *stats = bpf_map_lookup_elem(&bearer_matrix_map_5, &teid);
        if (stats) {
            stats->downlink_bytes += ctx->data_end - ctx->data;
            stats->total_pkts += 1;
        } else {
            struct bearer_stats initial = {
                .uplink_bytes = 0,
                .downlink_bytes = ctx->data_end - ctx->data,
                .total_pkts = 1,
            };
            bpf_map_update_elem(&bearer_matrix_map_5, &teid, &initial, BPF_ANY);
        }
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
