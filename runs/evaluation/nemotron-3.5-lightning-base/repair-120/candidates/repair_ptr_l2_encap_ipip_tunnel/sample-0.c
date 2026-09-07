#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Verify the original Ethernet header fits. */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Save the original Ethernet header contents. */
    struct ethhdr eth_saved = *eth;

    /* Push 20 bytes back for the outer IPv4 header. */
    if (bpf_xdp_adjust_head(ctx, -20))
        return XDP_DROP;

    /* Re-fetch pointers after the head adjustment so the verifier
       knows the register state is fresh. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;

    /* Re‑validate that there is enough room for the outer Ethernet
       header (14 bytes) plus the 20‑byte outer IPv4 header. */
    if ((void *)(eth + 1) + 20 > data_end)
        return XDP_PASS;

    /* Build the outer Ethernet header – copy the saved inner header
       as the payload that follows the new outer header. */
    struct ethhdr *new_eth = data;
    *new_eth = eth_saved;

    /* Set the outer protocol type to ETH_P_IP so the packet is
       processed as an IPv4 packet by subsequent hooks or the stack. */
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    /* Construct the outer IPv4 header (20 bytes) right after the
       Ethernet header.  The IP header starts at eth + 14. */
    struct iphdr *ip = (struct iphdr *)(new_eth + 1);

    /* Fill in the outer IPv4 header fields. */
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = bpf_htons(20);               /* only the header, no payload */
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_IPIP;               /* 4 */
    ip->saddr = 0;                             /* placeholder – caller may set */
    ip->daddr = 0;                             /* placeholder – caller may set */
    ip->check = 0;                             /* checksum will be filled in by stack */

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
