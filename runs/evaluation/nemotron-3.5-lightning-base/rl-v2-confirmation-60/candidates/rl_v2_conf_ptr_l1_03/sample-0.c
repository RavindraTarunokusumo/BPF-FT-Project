#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int xdp_ecn_rewrite(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Ensure this is an IPv4 packet (version field in tos/version union) */
    if (ip->version != 4)
        return XDP_PASS;

    /* Rewrite ECN codepoint to CE (0x03) in the TOS field */
    ip->tos = (ip->tos & 0xFC) | 0x03;

    /* Recalculate IPv4 header checksum over all 20 bytes */
    ip->check = 0;
    ip->check = bpf_csum_diff(0, ip, sizeof(struct iphdr), ip->check);

    /* Unconditionally forward the packet */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
