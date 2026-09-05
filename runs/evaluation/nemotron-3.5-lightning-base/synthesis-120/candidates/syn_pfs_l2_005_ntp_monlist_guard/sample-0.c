#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* NTP fixed header: 48 bytes, big-endian */
struct ntphdr {
    __be16  li_vn_mode;   /* 8 bits li, 3 bits vn, 3 bits mode */
    __be16  stratum;
    __be16  poll;
    __be16  precision;
    __be32  root_delay;
    __be32  root_dispersion;
    __be32  reference_id;
    __be32  reference_ts_sec;
    __be32  reference_ts_frac;
    __be32  origin_ts_sec;
    __be32  origin_ts_frac;
    __be32  recv_ts_sec;
    __be32  recv_ts_frac;
    __be32  transmit_ts_sec;
    __be32  transmit_ts_frac;
};

/* XDP program entry point */
SEC("xdp")
int xdp_ntp_monlist_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- Ethernet header validation --- */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 (ETH_P_IP = 0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* --- IPv4 header validation --- */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Must be UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* --- UDP header validation --- */
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* Verify UDP port 123 on source or destination */
    if (udp->source != htons(123) && udp->dest != htons(123))
        return XDP_PASS;

    /* --- NTP header validation --- */
    /* NTP header starts right after UDP header */
    struct ntphdr *ntp = (void *)udp + sizeof(*udp);
    if ((void *)ntp + sizeof(*ntp) > data_end)
        return XDP_PASS; /* malformed NTP header */

    /* Extract 3-bit Mode field from li_vn_mode (bits 0-2) */
    __u8 mode = ntohs(ntp->li_vn_mode) & 0x07;

    /* Drop Control (6) and Private/monlist (7) messages */
    if (mode == 6 || mode == 7)
        return XDP_DROP;

    /* Pass all other NTP modes (Client 3, Server 4, Broadcast 5) and non-NTP */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
