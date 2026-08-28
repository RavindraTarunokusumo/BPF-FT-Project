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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} proto_stats_11 SEC(".maps");

SEC("xdp")
int xdp_telemetry_pit_l2_011(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // FAULT: Key index not bounded before map lookup
    __u32 key = 10; 
    __u64 *cnt = bpf_map_lookup_elem(&proto_stats_11, &key);
    *cnt += 1; // NULL dereference

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
