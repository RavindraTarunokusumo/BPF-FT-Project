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
} srv6_sl_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l2_005_srv6_segment_left_histogram(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x86DD))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != 43)
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)ip + ip->ihl * 4;
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    if (ip6->nexthdr != 43)
        return XDP_PASS;

    struct ipv6_sr_hdr *srh = (void *)ip6 + sizeof(struct ipv6hdr);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;

    if (srh->routing_type != 4)
        return XDP_PASS;

    __u32 sl = srh->segments_left;
    __u32 key = (sl >= 4) ? 3 : sl;

    __u64 *cnt = bpf_map_lookup_elem(&srv6_sl_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
