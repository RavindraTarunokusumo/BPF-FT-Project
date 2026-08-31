#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __u32 vx_flags;
    __u32 vx_vni;
};

SEC("xdp")
int xdp_vxlan_decap(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    if (ip->ihl != 5)
        return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlanhdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    bpf_xdp_adjust_head(ctx, 50);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
