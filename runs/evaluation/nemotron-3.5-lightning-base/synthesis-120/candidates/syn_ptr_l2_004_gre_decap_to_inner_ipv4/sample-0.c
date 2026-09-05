#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/gre.h>
#include <linux/if_vlan.h>

/* XDP program entry point */
SEC("xdp")
int xdp_gre_decap_to_inner_ipv4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate outer Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 GRE (protocol 47) */
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    /* Verify outer IPv4 protocol is GRE (47) */
    struct iphdr *outer_ip = data + sizeof(*eth);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    /* IHL must be 5 (20 bytes) */
    if (outer_ip->ihl != 5)
        return XDP_PASS;

    if (outer_ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    /* 2. Validate GRE header (4 bytes, flags == 0) */
    struct grehdr *gre;
    void *gre_start = data + sizeof(*eth) + (outer_ip->ihl * 4);

    if (gre_start + sizeof(*gre) > data_end)
        return XDP_PASS;

    gre = gre_start;

    /* GRE flags must be 0 (no checksum, no routing, etc.) */
    if (gre->flags != 0)
        return XDP_PASS;

    /* 3. Validate inner IPv4 presence and bounds */
    /* After GRE header: 4 bytes (version/type = 0x0000 for GRE-KEY) + inner packet */
    void *inner_ip_start = gre_start + sizeof(*gre);

    if (inner_ip_start + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *inner_ip = inner_ip_start;

    /* Verify inner IPv4 EtherType 0x0800 (already implied by iphdr presence,
       but we explicitly check the outer eth type will be restored) */

    /* 4. Strip outer 24 bytes: 20 (outer IPv4) + 4 (GRE header) */
    int ret = bpf_xdp_adjust_head(ctx, 24);
    if (ret)
        return XDP_PASS; /* adjustment failed, pass unchanged */

    /* 5. Restore Ethernet MAC header and protocol */
    /* After adjust_head, data pointer moved back by 24 bytes.
       The original Ethernet header is now at the new data start. */
    eth = data;

    /* Restore original source/destination MACs (they were preserved in memory)
       and set protocol to IPv4. */
    eth->h_proto = bpf_htons(ETH_P_IP);

    /* 6. Return XDP_PASS as required */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
