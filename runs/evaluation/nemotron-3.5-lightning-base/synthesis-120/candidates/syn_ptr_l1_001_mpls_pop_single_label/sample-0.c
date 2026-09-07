#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/errno.h>

/* MPLS header definition (standard 4-byte label) */
struct mpls_label {
    __be32 label_and_exp:20;
    __be32 bos:1;
    __be32 ttl:8;
};

SEC("xdp")
int xdp_mpls_pop_single_label(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct mpls_label *mpls;

    /* 1. Validate Ethernet frame bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Verify EtherType == 0x8847 (MPLS Unicast) */
    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    /* 3. Validate MPLS label stack entry bounds */
    if (data + sizeof(*eth) + sizeof(*mpls) > data_end)
        return XDP_PASS;

    mpls = data + sizeof(*eth);

    /* 4. Verify BOS bit is 1 (Bottom of Stack) */
    if (!(mpls->bos))
        return XDP_PASS;

    /* 5. Pop the single MPLS label (4 bytes) */
    if (bpf_xdp_adjust_head(ctx, 4))
        return XDP_PASS;

    /* 6. Restore original MAC addresses and set EtherType to IPv4 */
    /*    bpf_xdp_adjust_head moves the data pointer forward by 4 bytes,
     *    effectively removing the label. The Ethernet header now starts
     *    at the original IP packet header location.
     *
     *    We reconstruct the Ethernet header fields:
     *    - h_dest: original source MAC (eth->h_source)
     *    - h_source: original destination MAC (eth->h_dest)
     *    - h_proto: ETH_P_IP (0x0800)
     *
     *    Note: The original source/destination MACs are preserved in
     *    eth->h_source and eth->h_dest respectively before adjustment.
     */
    eth->h_dest = eth->h_source;
    eth->h_source = (const unsigned char *)data; /* placeholder, usually kept */
    eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
