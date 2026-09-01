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

struct vxlan_hdr {
    __be32 flags;
    __be32 vni;
};

SEC("xdp")
int xdp_v2_pfs_l2_019(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    // FAULT: missing bounds check on IP header

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlan_hdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    __u32 vni = bpf_ntohl(vx->vni) >> 8;
    if (vni != 16283)
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    __u32 inner_ip_hlen = inner_ip->ihl * 4;
    if (inner_ip_hlen < sizeof(*inner_ip) || inner_ip_hlen > 60)
        return XDP_PASS;

    if (inner_ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)inner_ip + inner_ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if (tcp->dest == bpf_htons(9000))
            return XDP_DROP;
    } else if (inner_ip->protocol == IPPROTO_UDP) {
        struct udphdr *inner_udp = (void *)inner_ip + inner_ip_hlen;
        if ((void *)(inner_udp + 1) > data_end)
            return XDP_PASS;
        if (inner_udp->dest == bpf_htons(9000))
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
