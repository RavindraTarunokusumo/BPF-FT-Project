#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

struct srv6_hdr {
    __u8 nexthdr;
    __u8 hdr_ext_len;
    __u8 routing_type;
    __u8 segments_left;
    __u8 last_entry;
    __u8 flags;
    __u16 tag;
};

struct path_metrics {
    __u64 pkts;
    __u64 bytes;
    __u32 hops;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Path hash
    __type(value, struct path_metrics);
    __uint(max_entries, 1024);
} srv6_path_map SEC(".maps");

SEC("xdp")
int xdp_srv6_path_metrics(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;
    if (ip6->nexthdr != 43)
        return XDP_PASS;

    struct srv6_hdr *srh = (void *)(ip6 + 1);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;
    if (srh->routing_type != 4)
        return XDP_PASS;

    __u32 path_hash = 0;
    __u32 *sid_ptr = (void *)(srh + 1);

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if ((void *)(sid_ptr + 4) > data_end)
            break;
        path_hash ^= *sid_ptr ^ *(sid_ptr + 1) ^ *(sid_ptr + 2) ^ *(sid_ptr + 3);
        sid_ptr += 4;
    }

    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
    struct path_metrics *st = bpf_map_lookup_elem(&srv6_path_map, &path_hash);
    if (!st) {
        struct path_metrics new_st = {
            .pkts = 1,
            .bytes = pkt_len,
            .hops = srh->last_entry + 1,
            .pad = 0,
        };
        bpf_map_update_elem(&srv6_path_map, &path_hash, &new_st, BPF_ANY);
    } else {
        st->pkts += 1;
        st->bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
