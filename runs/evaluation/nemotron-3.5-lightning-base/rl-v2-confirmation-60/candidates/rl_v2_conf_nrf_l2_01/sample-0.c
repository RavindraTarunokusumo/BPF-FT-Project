#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP program entry point */
SEC("xdp")
int xdp_dual_uplink_xor(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Confirm eth->h_proto == ETH_P_IP */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Compute 2-tuple XOR hash: (ip->saddr ^ ip->daddr) */
    __u32 xor_hash = ip->saddr ^ ip->daddr;

    /* If LSB is 0, set eth->h_dest to 52:54:00:00:00:0a;
       if LSB is 1, set eth->h_dest to 52:54:00:00:00:0b */
    if (xor_hash & 1) {
        /* LSB is 1 -> destination 52:54:00:00:00:0b */
        eth->h_dest[0] = 0x52;
        eth->h_dest[1] = 0x54;
        eth->h_dest[2] = 0x00;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x0b;
    } else {
        /* LSB is 0 -> destination 52:54:00:00:00:0a */
        eth->h_dest[0] = 0x52;
        eth->h_dest[1] = 0x54;
        eth->h_dest[2] = 0x00;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x0a;
    }

    /* Return XDP_TX for routed packets, XDP_PASS for non-IP traffic */
    /* Since we already confirmed ETH_P_IP, we route */
    return XDP_TX;
}

char LICENSE[] = "GPL";
