#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* XDP action constants are defined in linux/if_xdp.h, but we use the values
   commonly expected or rely on the bpf_helpers.h inclusion. */

/* Program entry point */
SEC("xdp")
int nrf_l1_udp_reflector(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Ethernet Header Bounds Check */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Verify Ethernet Type == IPv4 (ETH_P_IP) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. IPv4 Header Bounds Check */
    /* iph is located immediately after eth_hdr */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 4. Verify IP Protocol == UDP (IPPROTO_UDP == 17) */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 5. UDP Header Bounds Check */
    /* udph is located immediately after iph */
    struct udphdr *udph = (struct udphdr *)(ip + 1);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    /* 6. Layer 2 MAC Address Swap */
    /* We use a temporary stack buffer to hold the destination MAC 
       while we overwrite it with the source, then place the saved 
       destination into the source field. */
    __u8 tmp_mac[6];

    /* Save Destination MAC (eth->h_dest) */
    bpf_memcpy(tmp_mac, eth->h_dest, 6);

    /* Copy Source MAC (eth->h_source) to Destination */
    bpf_memcpy(eth->h_dest, eth->h_source, 6);

    /* Copy saved Destination MAC to Source */
    bpf_memcpy(eth->h_source, tmp_mac, 6);

    /* 7. Reflect the packet */
    /* XDP_TX transmits the packet out the same interface. 
       The MAC swap has already been performed in-memory. */
    return XDP_TX;
}

/* License GPL */
char LICENSE[] = "GPL";
