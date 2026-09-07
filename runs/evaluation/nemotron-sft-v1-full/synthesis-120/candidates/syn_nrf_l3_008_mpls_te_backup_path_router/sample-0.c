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

struct mpls_hdr {
    __be32 label_and_tc;
    __be32 time_to_live;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} te_health_map SEC(".maps");

SEC("xdp")
int xdp_syn_nrf_l3_008_mpls_te_backup_path_router(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    struct mpls_hdr *mpls = (void *)(eth + 1);
    if ((void *)(mpls + 1) > data_end)
        return XDP_PASS;

    __u32 label = bpf_ntohl(mpls->label_and_tc) >> 20;
    if (label != 1000)
        return XDP_PASS;

    __u32 *health = bpf_map_lookup_elem(&te_health_map, &label);
    if (health) {
        if (*health == 1)
            return xdp_redirect_ifindex(ctx, 90);
        else
            return xdp_redirect_ifindex(ctx, 91);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
