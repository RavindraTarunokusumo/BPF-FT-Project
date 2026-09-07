/* XDP ECMP Route Distribution Program
 * Category: network_routing_forwarding
 * Task:   rl_v2_conf_nrf_l2_02
 * 
 * Distributes traffic across two gateways using LSB of (src XOR dst) XOR hash.
 * LSB == 0 -> Gateway A (52:54:00:00:00:0a)
 * LSB == 1 -> Gateway B (52:54:00:00:00:0b)
 * All other traffic is passed through.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int xdp_ecmp_distribute(struct xdp_md *ctx)
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

    /* Compute 2-tuple XOR hash and extract LSB */
    __u32 xor_hash = ip->saddr ^ ip->daddr;
    int lsb = xor_hash & 1;

    /* Select gateway MAC based on LSB */
    if (lsb == 0) {
        /* Gateway A */
        ((unsigned char *)eth->h_dest)[0] = 0x52;
        ((unsigned char *)eth->h_dest)[1] = 0x54;
        ((unsigned char *)eth->h_dest)[2] = 0x00;
        ((unsigned char *)eth->h_dest)[3] = 0x00;
        ((unsigned char *)eth->h_dest)[4] = 0x00;
        ((unsigned char *)eth->h_dest)[5] = 0x0a;
    } else {
        /* Gateway B */
        ((unsigned char *)eth->h_dest)[0] = 0x52;
        ((unsigned char *)eth->h_dest)[1] = 0x54;
        ((unsigned char *)eth->h_dest)[2] = 0x00;
        ((unsigned char *)eth->h_dest)[3] = 0x00;
        ((unsigned char *)eth->h_dest)[4] = 0x00;
        ((unsigned char *)eth->h_dest)[5] = 0x0b;
    }

    /* Return XDP_TX for routed packets */
    return XDP_TX;
}

char LICENSE[] = "GPL";
