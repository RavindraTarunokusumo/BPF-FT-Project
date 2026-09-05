#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

/* XDP entry point */
SEC("xdp")
int xdp_icmp_echo_drop(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Check Ethernet bounds: we need at least sizeof(struct ethhdr) */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* 2. Verify Ethernet protocol is IPv4 (ETH_P_IP == 0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Check IPv4 bounds: pointer must be within data_end */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    /* 4. Verify IP protocol is ICMP (IPPROTO_ICMP == 1) */
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    /* 5. Parse variable IHL safely.
       ip->ihl is the number of 32-bit words.
       The actual header length in bytes is ip->ihl * 4. */
    if (ip->ihl < 5) /* Minimum IHL is 5 (20 bytes) */
        return XDP_PASS;

    /* Optional: Re-verify IPv4 header fits within the packet using IHL.
       This prevents out-of-bounds reads if the packet is truncated. */
    if ((void *)ip + (ip->ihl * 4) > data_end)
        return XDP_PASS;

    /* 6. Parse ICMP header.
       ICMP header starts immediately after the IPv4 header.
       struct icmp has type and code at the start. */
    struct icmp *icmp = (struct icmp *)((void *)ip + (ip->ihl * 4));

    /* 7. Verify ICMP bounds: we need at least the type/code fields */
    if ((void *)icmp + sizeof(struct icmp) > data_end)
        return XDP_PASS;

    /* 8. Drop ICMP Echo Request (Type 8) */
    if (icmp->icmp_type == ICMP_ECHO) {
        return XDP_DROP;
    }

    /* 9. Pass all other packets */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
SEC("xdp")
struct xdp_program *xdp_icmp_echo_drop = (struct xdp_program *)&(struct xdp_program) {
    .ops = &xdp_ops,
    .owner = THIS_MODULE,
    .prog = (void *)xdp_icmp_echo_drop,
    .type = XDP_PROG_TYPE_XDP,
    .attach_point = XDP_ATTACH_TYPE_XDP,
};
