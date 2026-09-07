#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* XDP program entry point */
SEC("xdp")
int xdp_strip_outer_ipv4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Verify outer IPv4 header bounds */
    /* After Ethernet header, we expect an IPv4 header */
    struct iphdr *outer_ip = data + sizeof(struct ethhdr);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    /* Check if the outer protocol is IP-in-IP protocol 41 (IPv6) */
    if (outer_ip->protocol != IPPROTO_IPV6)
        return XDP_PASS;

    /* Calculate the outer IPv4 header length in bytes */
    /* ihl is in 32-bit words, so multiply by 4 */
    int outer_len = outer_ip->ihl * 4;

    /* Back up the original Ethernet header */
    /* We save the original h_proto value to restore it later if needed,
       though the task requires updating it to ETH_P_IPV6. */
    __be16 orig_h_proto = eth->h_proto;

    /* Update the Ethernet protocol type to ETH_P_IPV6 (0x86DD) */
    eth->h_proto = htons(ETH_P_IPV6);

    /* Adjust the packet head by the outer IPv4 header length.
       This effectively removes the outer IPv4 header, exposing the
       native IPv6 frame that was encapsulated inside. */
    int ret = bpf_xdp_adjust_head(ctx, outer_len);
    if (ret)
        return XDP_PASS;

    /* Restore the updated Ethernet header (which now points to the
       exposed IPv6 frame). Since bpf_xdp_adjust_head moved the data
       pointer, we need to re-establish the Ethernet header context. */
    /* After adjust_head, the Ethernet header is at the new data pointer.
       We update h_proto again to ensure it reflects the new frame type. */
    struct ethhdr *new_eth = data;
    new_eth->h_proto = htons(ETH_P_IPV6);

    /* Restore the original protocol if the program logic requires it,
       but per the task we set it to IPV6. */
    (void)orig_h_proto;

    /* Unconditionally pass the packet */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
