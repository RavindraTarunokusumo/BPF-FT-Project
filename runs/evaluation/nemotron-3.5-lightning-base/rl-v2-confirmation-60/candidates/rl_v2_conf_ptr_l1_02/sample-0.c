#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int xdp_ecn_mark(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Apply ECN congestion marking: set lowest 2 bits of TOS to 3 */
    ip->tos = (ip->tos & 0xFC) | 0x03;

    /* Recalculate IPv4 header checksum over all 20 bytes */
    ip->check = 0;
    ip->check = bpf_csum_diff(0, ip, sizeof(*ip), ip->check);

    /* Unconditionally forward the packet */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
