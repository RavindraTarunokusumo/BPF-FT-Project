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
} length_histogram SEC(".maps");

SEC("xdp")
int xdp_telemetry_pit_l2_length_histogram(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = (__u32)(data_end - data);

    __u32 slot = 0;
    if (pkt_len >= 512)
        slot = 3;
    else if (pkt_len >= 128)
        slot = 2;
    else if (pkt_len >= 64)
        slot = 1;

    __u64 *count = bpf_map_lookup_elem(&length_histogram, &slot);
    if (count)
        *count += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
