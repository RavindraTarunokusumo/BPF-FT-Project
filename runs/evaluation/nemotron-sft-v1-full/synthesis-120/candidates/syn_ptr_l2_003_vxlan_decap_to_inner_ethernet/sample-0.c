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

SEC("xdp")
int xdp_vxlan_decap_syn_ptr_l2_003_vxlan_decap_to_inner_ethernet(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    if (ip->ihl != 5)
        return XDP_PASS;

    unsigned int ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr))
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    if (udp->len < 8)
        return XDP_PASS;

    struct vxlan_hdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    unsigned char *d = inner_eth->h_dest;
    __builtin_memcpy(d, inner_eth->h_source, ETH_ALEN);
    __builtin_memcpy(inner_eth->h_source, d, ETH_ALEN);

    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, inner_eth->h_dest, ETH_ALEN);
    __builtin_memcpy(inner_eth->h_dest, inner_eth->h_source, ETH_ALEN);
    __builtin_memcpy(inner_eth->h_source, tmp_mac, ETH_ALEN);

    return bpf_xdp_adjust_head(ctx, 50);
}

char _license[] SEC("license") = "GPL";
