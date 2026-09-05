#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/gtp.h>

/* GTP-U header: 8 bytes (version/type + length + TEID) */
struct gtp_u_header {
    __be16 version_type; /* bits 15:8 = version (4), bits 7:0 = PT (0 for IPv4) */
    __be16 length;
    __be32 teid;
} __attribute__((packed));

SEC("xdp")
int xdp_gtpu_decap_to_inner_ipv4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate outer Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate outer IPv4 header (20 bytes minimum) */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Validate outer UDP header (8 bytes) and destination port 2152 */
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    /* 4. Validate GTP-U header (8 bytes) */
    struct gtp_u_header *gtpu = (void *)udp + sizeof(*udp);
    if ((void *)gtpu + sizeof(*gtpu) > data_end)
        return XDP_PASS;

    /* 5. Strip the outer 36 bytes: 20 (outer IPv4) + 8 (UDP) + 8 (GTP-U) */
    int ret = bpf_xdp_adjust_head(ctx, 36);
    if (ret)
        return XDP_PASS; /* adjustment failed; still pass to avoid dropping */

    /* 6. Restore Ethernet header pointers after adjustment */
    /* data now points to what was the inner Ethernet header */
    eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 7. Restore original Ethernet MAC addresses from the original frame.
       The original source and destination MACs are now at offset 36. */
    struct ethhdr *orig_eth = (void *)(data - 36 + sizeof(*eth));
    /* Note: orig_eth points to the original outer Ethernet header.
       We copy its fields back to the new leading eth. */
    eth->h_source[0] = orig_eth->h_source[0];
    eth->h_source[1] = orig_eth->h_source[1];
    eth->h_source[2] = orig_eth->h_source[2];
    eth->h_source[3] = orig_eth->h_source[3];
    eth->h_source[4] = orig_eth->h_source[4];
    eth->h_source[5] = orig_eth->h_source[5];
    eth->h_dest[0] = orig_eth->h_dest[0];
    eth->h_dest[1] = orig_eth->h_dest[1];
    eth->h_dest[2] = orig_eth->h_dest[2];
    eth->h_dest[3] = orig_eth->h_dest[3];
    eth->h_dest[4] = orig_eth->h_dest[4];
    eth->h_dest[5] = orig_eth->h_dest[5];

    /* 8. Set Ethernet protocol to IPv4 */
    eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char LICENSE[] = "GPL";
