#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* NTP header definition (RFC 5905).
 * The Stratum field is at offset 0 (1 byte).
 * We access byte offset 1 as required by the task.
 */
struct ntp_header {
    __u8  li_vn_mode;    /* byte 0: Leap indicator, version, mode */
    __u8  stratum;       /* byte 1: Stratum level (offset 1) */
    __u8  poll;          /* byte 2: Poll interval */
    __s8  precision;     /* byte 3: Precision */
    __u32 root_delay;    /* bytes 4-7: Root delay */
    __u32 root_disp;     /* bytes 8-11: Root dispersion */
    __u32 ref_id;        /* bytes 12-15: Reference identifier */
    __u32 ref_ts_sec;    /* bytes 16-19: Reference timestamp */
    __u32 ref_ts_frac;   /* bytes 20-23: Reference timestamp fraction */
    __u32 orig_ts_sec;   /* bytes 24-27: Originate timestamp */
    __u32 orig_ts_frac;  /* bytes 28-31: Originate timestamp fraction */
    __u32 recv_ts_sec;   /* bytes 32-35: Receive timestamp */
    __u32 recv_ts_frac;  /* bytes 36-39: Receive timestamp fraction */
    __u32 trans_ts_sec;  /* bytes 40-43: Transmit timestamp */
    __u32 trans_ts_frac; /* bytes 44-47: Transmit timestamp */
};

/* XDP program entry point */
SEC("xdp")
int xdp_stratum_clamp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Validate Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Validate IPv4 protocol */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Validate UDP protocol and port 123 */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    if (udp->dest != htons(123))
        return XDP_PASS;

    /* Validate NTP payload bounds */
    void *ntp_payload = (void *)udp + sizeof(*udp);
    if (ntp_payload + 1 > data_end)
        return XDP_PASS;

    /* Access the Stratum field at byte offset 1 of NTP payload */
    struct ntp_header *ntp = ntp_payload;
    __u8 stratum = ntp->stratum;

    /* Clamp stratum to max 4 if between 5 and 15 inclusive */
    if (stratum > 4 && stratum <= 15) {
        ntp->stratum = 4;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
