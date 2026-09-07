#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/ctx.h>

/* GTP-U header definition per 3GPP TS 29.281 */
struct gtpuhdr {
    __be8  version_npt;   /* bits 7:5 = version (4), bits 4:1 = PT (0xF), bit 0 = N-P */
    __be8  flags;
    __be16 length;
    __be32 teid;
} __attribute__((packed));

/* XDP program entry point */
SEC("xdp")
int xdp_gtpu_redirect(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate minimum Ethernet frame size */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate IPv4 protocol */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Validate UDP protocol and extract UDP header */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* 4. Verify UDP destination port is GTP-U (2152) */
    if (udp->dest != htons(2152))
        return XDP_PASS;

    /* 5. Validate GTP-U header bounds */
    struct gtpuhdr *gtp = (struct gtpuhdr *)(udp + 1);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*gtp) > data_end)
        return XDP_PASS;

    /* 6. Inspect TEID and redirect accordingly */
    __be32 teid = gtp->teid;

    if (teid == cpu_to_be32(0x0000A001)) {
        /* Redirect to target gNodeB interface ifindex 95 */
        return bpf_redirect(95, 0);
    }

    if (teid == cpu_to_be32(0x0000A002)) {
        /* Redirect to source gNodeB interface ifindex 96 */
        return bpf_redirect(96, 0);
    }

    /* 7. Pass all other TEIDs and non-matching traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
