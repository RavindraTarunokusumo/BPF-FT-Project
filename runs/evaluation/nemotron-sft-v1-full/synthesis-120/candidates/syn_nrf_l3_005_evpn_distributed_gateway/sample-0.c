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
int xdp_v2ray_syn_nrf_l3_005_evpn_distributed_gateway(struct xdp_md *ctx) {
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

    __be32 vni = vx->vni & bpf_htons(0xFFFFFF);
    if (vni != bpf_htons(5))
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_dest[0] != 0x00 || inner_eth->h_dest[1] != 0x00 ||
        inner_eth->h_dest[2] != 0x5e || inner_eth->h_dest[3] != 0x00 ||
        inner_eth->h_dest[4] != 0x01 || inner_eth->h_dest[5] != 0x01)
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
        if (tcp->dest == bpf_htons(80))
            return bpf_redirect(70, 0);
    } else if (inner_ip->protocol == IPPROTO_UDP) {
        struct udphdr *inner_udp = (void *)inner_ip + inner_ip_hlen;
        if ((void *)(inner_udp + 1) > data_end)
            return XDP_PASS;
        if (inner_udp->dest == bpf_htons(52)) {
            __u8 *d = (void *)(inner_udp + 1);
            if ((void *)(d + 32) > data_end)
                return XDP_PASS;
            if (d[0] == 'S' && d[1] == 'Y' && d[2] == 'N' && d[3] == '_' &&
                d[4] == 'N' && d[5] == 'R' && d[6] == 'F' && d[7] == '_' &&
                d[8] == 'L' && d[9] == '3' && d[10] == '_' && d[11] == '0' && d[12] == '0' && d[13] == '_' && d[14] == '5' && d[15] == '_' && d[16] == 'E' && d[17] == 'V' && d[18] == 'P' && d[19] == 'N' && d[20] == '_' && d[21] == 'D' && d[22] == 'I' && d[23] == 'S' && d[24] == 'T' && d[25] == 'R' && d[26] == 'I' && d[27] == 'B' && d[28] == 'U' && d[29] == 'T' && d[30] == '_' && d[31] == 'D' && d[32] == 'A' && d[33] == 'T' && d[34] == 'A') {
                return bpf_redirect(71, 0);
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
