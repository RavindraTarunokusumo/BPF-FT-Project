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
int xdp_distributed_gateway_evpn(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_VXLAN))
        return XDP_PASS;

    unsigned int eth_hdr_len = sizeof(struct ethhdr);
    if ((void *)eth + eth_hdr_len > data_end)
        return XDP_PASS;

    struct vxlan_hdr *vxlan = (void *)eth + eth_hdr_len;
    if ((void *)(vxlan + 1) > data_end)
        return XDP_PASS;

    if (vxlan->vni != 0x5e0001)
        return XDP_PASS;

    unsigned int vxlan_hdr_len = sizeof(struct vxlan_hdr);
    if ((void *)vxlan + vxlan_hdr_len > data_end)
        return XDP_PASS;

    void *inner_data = (void *)vxlan + vxlan_hdr_len;
    if (inner_data > data_end)
        return XDP_PASS;

    struct ethhdr *inner_eth = inner_data;
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    unsigned int inner_eth_hdr_len = sizeof(struct ethhdr);
    if ((void *)inner_eth + inner_eth_hdr_len > data_end)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)inner_eth + inner_eth_hdr_len;
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    __u8 *d = (void *)&inner_ip->daddr;
    if (d[0] == 10 && d[1] == 0 && d[2] == 1 && d[3] == 0x80)
        return bpf_redirect(70, 0);

    d[2] = 2;
    if (d[0] == 10 && d[1] == 0 && d[2] == 2 && d[3] == 0x80)
        return bpf_redirect(71, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
