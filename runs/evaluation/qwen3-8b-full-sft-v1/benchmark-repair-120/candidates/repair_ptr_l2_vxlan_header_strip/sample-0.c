#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    __u32 vxlan_hdr_len = sizeof(struct udphdr) + sizeof(struct vxlan_hdr);
    if ((void *)udp + vxlan_hdr_len > data_end)
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, 50))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    if ((void *)(data + 50) > data_end)
        return XDP_DROP;

    struct ethhdr *inner_eth = data;
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_DROP;

    __u16 proto = inner_eth->h_proto;
    if (proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    // Further processing of inner IP packet
    // ...

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
