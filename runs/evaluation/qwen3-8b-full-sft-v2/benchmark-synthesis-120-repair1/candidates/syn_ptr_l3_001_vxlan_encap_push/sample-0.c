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
int xdp_vxlan_encap_ptr_l3_001_vxlan_encap_push(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_DROP;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    if (bpf_xdp_adjust_head(ctx, -50))
        return XDP_DROP;

    struct ethhdr *new_eth = data;
    struct iphdr *new_ip = (void *)(new_eth + 1);
    struct udphdr *udp = (void *)(new_ip + 1);
    struct vxlan_hdr *vx = (void *)(udp + 1);

    __builtin_memcpy(new_eth->h_dest, (void *)&(192,168,1,254), ETH_ALEN);
    __builtin_memcpy(new_eth->h_source, (void *)&(192,168,1,1), ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    new_ip->protocol = IPPROTO_UDP;
    new_ip->check = 0;
    new_ip->check = bpf_csum_diff(0, 0, (void *)new_ip, sizeof(*new_ip));

    udp->source = bpf_htons(4789);
    udp->dest = bpf_htons(4789);
    udp->len = bpf_ntohs(udp->len) + sizeof(*vx);
    __builtin_memcpy((void *)&udp->dest, &(4789), sizeof(udp->dest));

    vx->flags = bpf_htons(0x0800);
    vx->vni = bpf_htons(100);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";