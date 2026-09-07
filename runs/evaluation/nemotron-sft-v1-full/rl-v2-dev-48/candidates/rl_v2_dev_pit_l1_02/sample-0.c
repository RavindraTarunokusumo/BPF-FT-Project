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
} size_hist_2 SEC(".maps");

SEC("xdp")
int xdp_telemetry_rl_v2_dev_pit_l1_02(struct xdp_md *ctx) {
    __u32 len = (__u32)(ctx->data_end - ctx->data);
    __u32 bin = 0;

    if (len < 128)
        bin = 0;
    else if (len < 512)
        bin = 1;
    else if (len < 1024)
        bin = 2;
    else
        bin = 3;

    __sync_fetch_and_add(&size_hist_2.values[bin], 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
