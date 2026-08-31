#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct bearer_stats {
    __u64 uplink_bytes;
    __u64 downlink_bytes;
    __u64 total_pkts;
};

struct gtpuhdr {
    __u8 flags;
    __u8 msg_type;
    __be16 length;
    __be32 teid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // TEID
    __type(value, struct bearer_stats);
    __uint(max_entries, 1024);
} bearer_matrix_map SEC(".maps");

SEC("xdp")
int xdp_gtpu_bearer_matrix(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    int is_uplink = (udp->dest == bpf_htons(2152));
    int is_downlink = (udp->source == bpf_htons(2152));
    if (!is_uplink && !is_downlink)
        return XDP_PASS;

    struct gtpuhdr *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > data_end)
        return XDP_PASS;

    __u32 teid = bpf_ntohl(gtp->teid);
    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);

    struct bearer_stats *st = bpf_map_lookup_elem(&bearer_matrix_map, &teid);
    if (!st) {
        struct bearer_stats new_st = {
            .uplink_bytes = is_uplink ? pkt_len : 0,
            .downlink_bytes = is_downlink ? pkt_len : 0,
            .total_pkts = 1,
        };
        bpf_map_update_elem(&bearer_matrix_map, &teid, &new_st, BPF_ANY);
    } else {
        if (is_uplink)
            st->uplink_bytes += pkt_len;
        else
            st->downlink_bytes += pkt_len;
        st->total_pkts += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
