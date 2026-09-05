#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP program entry point */
SEC("xdp")
int xdp_set_ce_flag(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds and protocol */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Assert Congestion Experienced flag in IPv4 TOS byte.
     * Set lowest 2 bits to 0x03: (ip->tos & 0xFC) | 0x03 */
    ip->tos = (ip->tos & 0xFC) | 0x03;

    /* Recalculate IPv4 header checksum over all 20 bytes.
     * bpf_l3_csum_replace performs an in-place checksum update.
     * We replace the entire 16-bit checksum field (offset 10, 2 bytes)
     * with a new value computed over the 20-byte header. */
    bpf_l3_csum_replace(ip, sizeof(*ip), 0, ip->check, IPPROTO_IP);

    /* Unconditionally forward the packet */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
