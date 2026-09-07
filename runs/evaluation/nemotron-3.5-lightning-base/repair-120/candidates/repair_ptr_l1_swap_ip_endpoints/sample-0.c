#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Verify Ethernet header fits within the packet. */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic. */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header fits within the packet bounds. */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Swap source and destination IP addresses. */
    __be32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;

    /* IPv4 header checksum is invariant under endpoint swap
     * (sum of addresses is identical), so no checksum update is needed. */

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
