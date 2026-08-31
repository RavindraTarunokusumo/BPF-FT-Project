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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=SL 0, 1=SL 1, 2=SL 2, 3=SL 3+
} srv6_sl_map SEC(".maps");

SEC("xdp")
int xdp_srv6_sl_histogram(struct xdp_md *ctx) {
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

    // Next Header 43 indicates IPv6 Routing Header
    if (ip6->nexthdr != 43)
        return XDP_PASS;

    struct srv6_hdr *srh = (void *)(ip6 + 1);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;

    if (srh->routing_type != 4) // Routing Type 4 = SRH (SRv6)
        return XDP_PASS;

    __u32 key = srh->segments_left;
    if (key > 3)
        key = 3;

    __u64 *cnt = bpf_map_lookup_elem(&srv6_sl_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
