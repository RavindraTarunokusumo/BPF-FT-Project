#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/ctx/sk_buff.h>

/* GTP-U header definition per 3GPP TS 29.281 */
struct gtpuhdr {
    __be32 teid;        /* Tunnel Endpoint Identifier */
    /* Optional header extension and payload follow */
} __attribute__((packed));

/* XDP program entry point */
SEC("xdp")
int xdp_gtpu_teid_remap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet frame presence and minimum size */
    struct ethhdr *eth;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Only process IPv4 packets (EtherType 0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 2. Validate IPv4 header presence and size */
    struct iphdr *ip;
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);
    /* Basic IPv4 header validation: IHL must be >= 5 (20 bytes) */
    if (ip->ihl < 5)
        return XDP_PASS;

    /* 3. Validate UDP header presence and size */
    struct udphdr *udp;
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
        return XDP_PASS;

    udp = data + sizeof(*eth) + ip->ihl * 4;

    /* 4. Verify UDP destination port is GTP-U (2152) */
    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    /* 5. Validate GTP-U header presence and size */
    struct gtpuhdr *gtp;
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) + sizeof(*gtp) > data_end)
        return XDP_PASS;

    gtp = data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp);

    /* 6. Verify GTP-U TEID is the target value 0x1000 */
    if (gtp->teid != bpf_htonl(0x1000))
        return XDP_PASS;

    /* 7. Remap TEID from 0x1000 to 0x2000 */
    gtp->teid = bpf_htonl(0x2000);

    /* 8. Rewrite outer destination IPv4 address to 198.51.100.1 */
    /* 198.51.100.1 in network byte order */
    ip->daddr = bpf_htonl(0xC6336401UL);

    /* 9. Recalculate IPv4 checksum */
    /* ip_fast_csum is the standard BPF helper for IPv4 header checksum recalculation.
       It operates on the first (ihl * 4) bytes of the IP header. */
    ip->check = 0;
    ip->check = ip_fast_csum((unsigned char *)ip, ip->ihl);

    /* 10. Return XDP_PASS as required */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
