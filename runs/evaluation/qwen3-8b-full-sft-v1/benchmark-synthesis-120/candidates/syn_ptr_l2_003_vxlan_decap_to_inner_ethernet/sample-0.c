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
int xdp_transform_syn_ptr_l2_003_vxlan_decap_to_inner_ethernet(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    if (udp->dgram_len < (unsigned int)sizeof(struct ethhdr))
        return XDP_PASS;

    __u8 *p = (void *)udp + udp_hdr_len;
    if ((void *)p < (void *)ip + ip_hdr_len)
        return XDP_PASS;

    unsigned int vxlan_hdr_len = sizeof(struct vxlan_hdr);
    if ((void *)p + vxlan_hdr_len > data_end)
        return XDP_PASS;

    struct vxlan_hdr *vxlan = (void *)p;
    if (vxlan->vni != 0x3)
        return XDP_PASS;

    p += vxlan_hdr_len;
    if ((void *)p < (void *)udp + udp_hdr_len)
        return XDP_PASS;

    if (data_end - p < sizeof(struct ethhdr))
        return XDP_PASS;

    __u64 new_head = (__u64)data + (p - (void *)data);
    if (new_head < (__u64)data || new_head + sizeof(struct ethhdr) > (__u64)data_end)
        return XDP_PASS;

    __builtin_memcpy((void *)data, p, data_end - p);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
