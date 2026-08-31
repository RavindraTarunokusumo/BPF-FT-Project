#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=TCP(6), 1=UDP(17), 2=ICMPv6(58), 3=Other
} ipv6_proto_map SEC(".maps");

SEC("xdp")
int xdp_ipv6_proto_split(struct xdp_md *ctx) {
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

    __u32 key = 3; // Other
    if (ip6->nexthdr == IPPROTO_TCP)
        key = 0;
    else if (ip6->nexthdr == IPPROTO_UDP)
        key = 1;
    else if (ip6->nexthdr == IPPROTO_ICMPV6)
        key = 2;

    __u64 *cnt = bpf_map_lookup_elem(&ipv6_proto_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
