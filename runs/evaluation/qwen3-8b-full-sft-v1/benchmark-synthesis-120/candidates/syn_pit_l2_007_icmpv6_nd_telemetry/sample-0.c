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


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} nd_telemetry_map_7 SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l2_007_icmpv6_nd(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    if (ip6->protocol != IPPROTO_ICMPV6)
        return XDP_PASS;

    struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
    if ((void *)(icmp6 + 1) > data_end)
        return XDP_PASS;

    __u32 type = icmp6->icmp6_type;
    if (type >= 133 && type <= 136) {
        __u32 key = type - 133;
        __u64 *cnt = bpf_map_lookup_elem(&nd_telemetry_map_7, &key);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
