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

struct mpls_label {
    __u32 label;
    __u32 bos;
    __u32 ttl;
    __u32 next;
};

SEC("xdp")
int xdp_route_syn_nrf_l2_001_mpls_routing_table_redirect(struct xdp_md *ctx) {
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

    __u32 label = mpls->label & 0xFFFFF; // Extract 20-bit label

    if (label == 500) {
        return bpf_redirect(20, 0);
    } else if (label == 600) {
        return bpf_redirect(21, 0);
    }

    // Check if the route exists in the map
    __u32 key = label;
    __u32 *val = bpf_map_lookup_elem(&mpls_route_map, &key);
    if (val) {
        return bpf_redirect(*val, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
