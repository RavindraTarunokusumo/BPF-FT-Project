#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/gre.h>

/* XDP program: GRE Key Present flag stripper */
SEC("xdp")
int xdp_gre_strip_key_flag(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Validate Ethernet frame */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Validate IPv4 payload */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Must be GRE (protocol 47) */
    if (ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    /* Validate and access GRE header */
    struct grehdr *gre = (struct grehdr *)(ip + 1);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*gre) > data_end)
        return XDP_PASS;

    /* Clear Key Present flag (bit 13 / 0x2000) in host byte order */
    gre->flags &= ~0x2000;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
