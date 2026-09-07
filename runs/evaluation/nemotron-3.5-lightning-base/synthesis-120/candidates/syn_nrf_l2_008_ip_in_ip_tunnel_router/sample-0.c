#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/ctx/sk_buff.h>

/* XDP program entry point */
SEC("xdp")
int xdp_ip_in_ip_router(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Validate outer Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Validate outer IPv4 header (protocol 4 = IP-in-IP) */
    struct iphdr *outer_ip = (struct iphdr *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (outer_ip->protocol != IPPROTO_IPIP) /* 4 */
        return XDP_PASS;

    /* 3. Validate inner IPv4 header offset and bounds */
    /* Inner IP starts right after the outer IP header */
    void *inner_ip_start = (void *)(outer_ip + 1);
    struct iphdr *inner_ip = inner_ip_start;

    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    /* Verify inner IP version is IPv4 (IHL already validated by bounds check) */
    if (inner_ip->version != 4)
        return XDP_PASS;

    /* 4. Inspect inner destination address */
    __be32 inner_dst = inner_ip->daddr;

    if (inner_dst >= 0x0A010000 && inner_dst <= 0x0A01FFFF) /* 10.1.0.0/16 */
        return bpf_redirect(18, 0);

    if (inner_dst >= 0x0A020000 && inner_dst <= 0x0A02FFFF) /* 10.2.0.0/16 */
        return bpf_redirect(19, 0);

    /* 5. Pass unrouted / other traffic */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
