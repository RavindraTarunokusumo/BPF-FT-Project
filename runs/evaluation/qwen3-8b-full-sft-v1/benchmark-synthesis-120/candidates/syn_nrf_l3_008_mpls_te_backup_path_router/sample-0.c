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
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} te_health_map_8 SEC(".maps");

SEC("xdp")
int xdp_telemetry_frr_nrf_l3_008(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    struct mpls_label *mpls = (void *)(eth + 1);
    if ((void *)(mpls + 1) > data_end)
        return XDP_PASS;

    if (mpls->label != 1000)
        return XDP_PASS;

    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&te_health_map_8, &key);
    if (!val) {
        // Map not initialized, pass
        return XDP_PASS;
    }

    if (*val == 1) {
        // Primary tunnel UP, redirect to ifindex 90
        return bpf_redirect_map(&te_health_map_8, 90, 0);
    } else {
        // Primary tunnel DOWN, fail over to backup ifindex 91
        return bpf_redirect_map(&te_health_map_8, 91, 0);
    }
}

char _license[] SEC("license") = "GPL";
