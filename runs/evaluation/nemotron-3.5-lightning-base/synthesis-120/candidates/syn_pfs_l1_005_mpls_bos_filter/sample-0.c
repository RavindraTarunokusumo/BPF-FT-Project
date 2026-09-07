#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/ctx/skb.h>

/* XDP program entry point */
SEC("xdp")
int xdp_mpls_bos_filter(struct xdp_md *ctx)
{
    void *data_end;
    void *data;

    /* Obtain data and data_end pointers for bounds checking */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet header bounds and check EtherType 0x8847 */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS; /* truncated Ethernet frame */

    /* Check for MPLS Unicast EtherType */
    if (eth->h_proto != bpf_htons(ETH_TYPE_MPLS_UNICAST))
        return XDP_PASS; /* non-MPLS traffic */

    /* 2. Validate 4-byte MPLS label header bounds */
    /* MPLS shim header is exactly 4 bytes after the Ethernet header */
    struct mpls_hdr *mpls = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*mpls) > data_end)
        return XDP_PASS; /* truncated MPLS label */

    /* 3. Extract 32-bit label entry and check BOS bit (bit 8 = 0x00000100) */
    uint32_t label_entry = bpf_ntohl(mpls->label);
    /* BOS bit is bit 8 in the 32-bit big-endian representation.
       After ntohl conversion, BOS corresponds to bit 0 of the MSB byte,
       which is bit 31 of the native uint32_t. We check for 0x00000100
       after ntohl because the MPLS label is defined as big-endian. */
    if (label_entry & 0x00000100)
        /* BOS = 1: more labels may follow or this is the last label;
           per spec, we PASS single-label MPLS and non-MPLS. */
        return XDP_PASS;
    else
        /* BOS = 0: more labels follow in the stack -> drop */
        return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
