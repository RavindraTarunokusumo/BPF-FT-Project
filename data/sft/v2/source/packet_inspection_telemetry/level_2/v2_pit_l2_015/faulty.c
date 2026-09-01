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
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} pkt_hist SEC(".maps");

SEC("xdp")
int xdp_v2_pit_l2_015(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 len = (__u32)(data_end - data);
    __u32 key; // FAULT: uninitialized stack variable

    if (len < 64)
        key = 0;
    else if (len < 128)
        key = 1;
    else if (len < 512)
        key = 2;
    else if (len < 1024)
        key = 3;
    else
        key = 4;

    __u64 *val = bpf_map_lookup_elem(&pkt_hist, &key);
    if (val)
        *val += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
