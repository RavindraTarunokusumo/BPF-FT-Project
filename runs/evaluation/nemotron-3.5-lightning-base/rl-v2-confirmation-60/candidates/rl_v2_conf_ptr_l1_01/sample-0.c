#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int xdp_mark_ce(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 payload bounds */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Mark IPv4 TOS with Congestion Experienced (CE) bits: 0x03 */
    ip->tos = (ip->tos & 0xFC) | 0x03;

    /* Recalculate IPv4 header checksum over all 20 bytes */
    ip->check = 0;
    ip->check = bpf_csum_diff((unsigned long)ip,
                              sizeof(struct iphdr),
                              0,
                              0);
    /* Note: bpf_csum_diff semantics: subtract old, add new.
       Since we zeroed check first, this effectively recomputes
       the checksum over the 20-byte header. */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
