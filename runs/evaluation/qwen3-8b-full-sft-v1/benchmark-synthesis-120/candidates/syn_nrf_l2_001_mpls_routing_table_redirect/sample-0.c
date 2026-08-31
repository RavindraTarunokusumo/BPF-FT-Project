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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} mpls_route_table_1 SEC(".maps");

SEC("xdp")
int xdp_mpls_route_syn_nrf_l2_001(struct xdp_md *ctx) {
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

    __u32 label = mpls->label;
    if (label >= (1 << 20))
        return XDP_PASS;

    __u32 *egress = bpf_map_lookup_elem(&mpls_route_table_1, &label);
    if (egress) {
        return bpf_redirect(*egress, 0);
    }

    // Special cases
    if (label == 500)
        return bpf_redirect(20, 0);
    if (label == 600)
        return bpf_redirect(21, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
