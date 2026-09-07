#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* XDP entry point */
SEC("xdp")
int xdp_gre_decap(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify outer IPv4 header bounds */
    struct iphdr *outer_ip = (struct iphdr *)(eth + 1);
    if ((void *)outer_ip + (outer_ip->ihl * 4) > data_end)
        return XDP_PASS;

    /* Check if outer protocol is GRE (47) */
    if (outer_ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    /* Calculate total encapsulation length: (outer_ip->ihl * 4) + 4 bytes GRE header */
    int outer_len = outer_ip->ihl * 4;
    int encap_len = outer_len + 4;

    /* Back up Ethernet header pointer and shift packet head forward */
    /* bpf_xdp_adjust_head returns 0 on success, negative on failure */
    if (bpf_xdp_adjust_head(ctx, encap_len, 0))
        return XDP_PASS;

    /* Re-validate packet pointers after head adjustment */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify new Ethernet header bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Restore Ethernet header with ETH_P_IP (0x0800) */
    eth->h_proto = htons(ETH_P_IP);

    /* Packet successfully decapsulated; forward with XDP_PASS */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
