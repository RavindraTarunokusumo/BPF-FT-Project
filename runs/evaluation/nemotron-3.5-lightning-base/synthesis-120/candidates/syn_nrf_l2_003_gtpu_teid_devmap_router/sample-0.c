#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/ctx/sk_buff.h>

/* GTP-U header definition per 3GPP TS 29.281 */
struct gtpuhdr {
    __be16  flags_and_seq_no; /* bits: 0-3 = version, 4-7 = PT, 8-15 = length */
    __be32  teid;             /* Tunnel Endpoint Identifier */
    /* Optional: sequence number, spare, etc. follow */
};

/* XDP program entry point */
SEC("xdp")
int xdp_gtpu_teid_router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct gtpuhdr *gtpu;

    /* 1. Validate Ethernet frame minimum size */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Check Ethernet type: only IPv4 (0x0800) */
    if (eth->h_proto != bpf_htonl(ETH_P_IP))
        return XDP_PASS;

    /* 3. Validate IPv4 header */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);
    /* Verify IPv4 IHL is at least 5 (20 bytes) and total length fits */
    if (ip->ihl < 5 || ip->ihl * 4 > data_end - (void *)ip)
        return XDP_PASS;

    /* 4. Verify protocol is UDP (protocol number 17) */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 5. Validate UDP header and compute payload start */
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
        return XDP_PASS;

    udp = (void *)ip + ip->ihl * 4;
    /* Verify UDP destination port is GTP-U (2152) */
    if (udp->dest != bpf_htonl(2152))
        return XDP_PASS;

    /* 6. Validate GTP-U header bounds */
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) + sizeof(*gtpu) > data_end)
        return XDP_PASS;

    gtpu = (void *)udp + sizeof(*udp);

    /* 7. Check GTP-U version (must be 0x01) and PT bit (must be 0x01 for PDU) */
    /* flags_and_seq_no layout: bits 0-3 version, bits 4-7 PT, bits 8-15 length */
    if ((gtpu->flags_and_seq_no & bpf_htonl(0x0000000F)) != bpf_htonl(0x00000001))
        return XDP_PASS;
    if ((gtpu->flags_and_seq_no & bpf_htonl(0x000000F0)) != bpf_htonl(0x00000010))
        return XDP_PASS;

    /* 8. Extract TEID (network byte order, convert to host for comparison) */
    __u32 teid = ntohl(gtpu->teid);

    /* 9. Dispatch based on TEID */
    if (teid == 0x00000100) {
        /* Redirect to slice 1 interface ifindex 30 */
        return bpf_redirect(30, 0);
    }
    if (teid == 0x00000200) {
        /* Redirect to slice 2 interface ifindex 31 */
        return bpf_redirect(31, 0);
    }

    /* 10. Pass all other TEIDs and non-matching traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
