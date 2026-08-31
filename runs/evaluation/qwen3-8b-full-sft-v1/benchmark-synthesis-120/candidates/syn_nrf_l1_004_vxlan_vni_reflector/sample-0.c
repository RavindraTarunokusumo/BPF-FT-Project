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
int xdp_transform_syn_nrf_l1_004_vxlan_vni_reflector(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_VXLAN))
        return XDP_PASS;

    struct vxlanhdr *vxlan = (void *)(eth + 1);
    if ((void *)(vxlan + 1) > data_end)
        return XDP_PASS;

    __u16 vxlan_port = vxlan->vni >> 12;
    if (vxlan_port != 4789)
        return XDP_PASS;

    __u32 vni = vxlan->vni & 0xFFFFF;
    if (vni != 100)
        return XDP_PASS;

    struct iphdr *ip = (void *)(vxlan + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    unsigned char tmp[ETH_ALEN];
    __builtin_memcpy(tmp, ip->saddr, ETH_ALEN);
    __builtin_memcpy(ip->saddr, ip->daddr, ETH_ALEN);
    __builtin_memcpy(ip->daddr, tmp, ETH_ALEN);

    __u16 tmp_port = ip->check;
    ip->check = 0;
    __u16 *p = (__u16 *)ip + 10;
    if ((void *)(p + 1) <= data_end) {
        tmp_port = *p;
        *p = ip->check;
        ip->check = tmp_port;
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
