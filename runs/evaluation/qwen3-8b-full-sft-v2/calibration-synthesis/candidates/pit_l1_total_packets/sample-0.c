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
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} total_packet_counter SEC(".maps");

SEC("xdp")
int xdp_telemetry_pit_l1_total_packets(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&total_packet_counter, &key);
    if (val) {
        *val += 1;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
