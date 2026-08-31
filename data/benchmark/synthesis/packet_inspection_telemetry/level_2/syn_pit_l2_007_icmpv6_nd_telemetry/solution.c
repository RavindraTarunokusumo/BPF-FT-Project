#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=RS(133), 1=RA(134), 2=NS(135), 3=NA(136)
} nd_telemetry_map SEC(".maps");

SEC("xdp")
int xdp_nd_telemetry(struct xdp_md *ctx) {
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
    if (ip6->nexthdr != IPPROTO_ICMPV6)
        return XDP_PASS;

    struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
    if ((void *)(icmp6 + 1) > data_end)
        return XDP_PASS;

    __u8 type = icmp6->icmp6_type;
    if (type >= 133 && type <= 136) {
        __u32 key = type - 133;
        __u64 *cnt = bpf_map_lookup_elem(&nd_telemetry_map, &key);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
