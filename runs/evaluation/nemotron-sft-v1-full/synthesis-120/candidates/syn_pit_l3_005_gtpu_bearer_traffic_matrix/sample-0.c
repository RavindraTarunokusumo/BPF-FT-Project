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
} bearer_matrix_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l3_005_gtpu_bearer_traffic_matrix(struct xdp_md *ctx) {
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

    __u32 teid = 0;
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        if (udp->dest == bpf_htons(2152)) {
            teid = udp->source;
        } else if (udp->source == bpf_htons(2152)) {
            teid = udp->dest;
        }
    }

    if (teid) {
        struct bearer_stats *stats = bpf_map_lookup_elem(&bearer_matrix_map, &teid);
        if (stats) {
            if (udp->dest == bpf_htons(2152)) {
                stats->uplink_bytes += ip->tot_len;
                stats->total_pkts += 1;
            } else if (udp->source == bpf_htons(2152)) {
                stats->downlink_bytes += ip->tot_len;
                stats->total_pkts += 1;
            }
        } else {
            struct bearer_stats initial = {};
            if (udp->dest == bpf_htons(2152)) {
                initial.uplink_bytes = ip->tot_len;
                initial.total_pkts = 1;
            } else if (udp->source == bpf_htons(2152)) {
                initial.downlink_bytes = ip->tot_len;
                initial.total_pkts = 1;
            }
            bpf_map_update_elem(&bearer_matrix_map, &teid, &initial, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
