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
} win_dist_02 SEC(".maps");

SEC("xdp")
int xdp_telemetry_rl_v2_dev_pit_l3_02(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int win_bucket = 0;
    __u32 window = (__u32)bpf_ntohs(ip->window);
    if (window < 4096)
        win_bucket = 0;
    else if (window < 16384)
        win_bucket = 1;
    else if (window < 65535)
        win_bucket = 2;
    else
        win_bucket = 3;

    __sync_fetch_and_add(&win_dist_02.values[win_bucket], 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
