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
int xdp_vxlan_flags_filter(struct xdp_md *ctx) {
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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlanhdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    __u32 flags = bpf_ntohl(vx->vx_flags);
    // Standard VXLAN flag has bit 27 set (0x08000000). Any other bits in flags are reserved.
    if ((flags & 0xF7FFFFFF) != 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
