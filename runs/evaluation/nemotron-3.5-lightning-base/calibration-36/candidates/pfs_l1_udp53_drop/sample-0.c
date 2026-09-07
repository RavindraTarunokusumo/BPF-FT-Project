#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* XDP program entry point */
SEC("xdp")
int xdp_udp53_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Check Ethernet bounds: ensure we have at least an Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Verify Ethernet protocol is IPv4 (ETH_P_IP == 0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify we have enough room for the IPv4 header */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 4. Verify IP protocol is UDP (IPPROTO_UDP == 17) */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 5. Parse variable IHL safely.
       ip->ihl is the number of 32-bit words.
       Multiply by 4 to get bytes. Check bounds again. */
    if (ip->ihl < 5) /* minimum IHL is 5 (20 bytes) */
        return XDP_PASS;

    void *udp_start = data + sizeof(*eth) + (ip->ihl * 4);
    if (udp_start + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    /* 6. Parse UDP header and check destination port */
    struct udphdr *udp = udp_start;
    if (udp->dest == bpf_htons(53)) {
        /* Drop DNS traffic */
        return XDP_DROP;
    }

    /* 7. Pass all other traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
