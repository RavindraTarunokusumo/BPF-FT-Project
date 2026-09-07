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

    /* Verify the Ethernet header fits */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    /* Verify the IP header fits */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only process UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    /* Verify IP header length is valid and fits */
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    /* Verify the UDP header fits */
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Identify VXLAN packets on UDP port 4789 */
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    /* Strip 50 bytes: outer Ethernet (14) + IPv4 (20) + UDP (8) + VXLAN (8) */
    if (bpf_xdp_adjust_head(ctx, 50))
        return XDP_DROP;

    /* Re-validate packet boundaries after decap */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data >= data_end)
        return XDP_PASS;

    /* At this point the inner frame starts at `data`; the verifier will
       now be able to safely access the inner Ethernet header. */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
