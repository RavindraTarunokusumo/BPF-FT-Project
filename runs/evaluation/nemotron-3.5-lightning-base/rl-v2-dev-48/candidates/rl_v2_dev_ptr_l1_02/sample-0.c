#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int xdp_hop_reducer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds (minimum 20 bytes) */
    if ((void *)(eth + 1) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    /* Only process IPv4 packets (version == 4) */
    if (ip->version != 4)
        return XDP_PASS;

    /* Decrement TTL if > 1 */
    if (ip->ttl > 1)
        ip->ttl--;

    /* Recalculate IPv4 header checksum over all 20 bytes.
     * bpf_l3_csum_replace updates the checksum in-place.
     * We replace the entire 20-byte header checksum with a
     * recalculated value by passing the original checksum as
     * the replacement source (effectively forcing a full recompute). */
    bpf_l3_csum_replace(&ip->check, ip, data, sizeof(struct iphdr), 0);

    /* Unconditionally pass the packet */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
