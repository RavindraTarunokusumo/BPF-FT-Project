#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP program entry point */
SEC("xdp")
int xdp_route_even(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
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

    /* Extract Least Significant Bit */
    int lsb = xor_hash & 1;

    /* Route based on LSB */
    if (lsb == 0) {
        /* LSB is 0 -> route to gateway A */
        eth->h_dest[0] = 0x34; /* 52 */
        eth->h_dest[1] = 0x54;
        eth->h_dest[2] = 0x00;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x0a; /* 10 */
    } else {
        /* LSB is 1 -> route to gateway B */
        eth->h_dest[0] = 0x34; /* 52 */
        eth->h_dest[1] = 0x54;
        eth->h_dest[2] = 0x00;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x0b; /* 11 */
    }

    /* Return XDP_TX for routed packets */
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
