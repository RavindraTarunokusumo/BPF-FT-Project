#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Helper to safely access packet data within bounds */
static __always_inline struct eth_hdr *
eth_hdr(const struct xdp_md *xdpmd)
{
    return (struct eth_hdr *)xdpmd->data;
}

static __always_inline struct iphdr *
ip_hdr(const struct xdp_md *xdpmd)
{
    struct eth_hdr *eth = eth_hdr(xdpmd);
    /* Ethernet header is 14 bytes, IPv4 header starts after it */
    if ((void *)(eth + 1) > (void *)xdpmd->data_end)
        return NULL;
    return (struct iphdr *)(eth + 1);
}

static __always_inline struct tcphdr *
tcp_hdr(const struct xdp_md *xdpmd)
{
    struct iphdr *ip = ip_hdr(xdpmd);
    if (!ip)
        return NULL;
    /* IPv4 header length is in 32-bit words, offset to TCP header */
    int ip_hdr_len = ip->ihl * 4;
    if ((void *)(ip + 1) > (void *)xdpmd->data_end)
        return NULL;
    return (struct tcphdr *)((void *)ip + ip_hdr_len);
}

/* Parse TCP options and find MSS option (Kind=2, Length=4) */
static __always_inline __u16 *
find_mss_option(struct tcphdr *tcp, struct tcphdr *tcp_end)
{
    /* TCP header without options starts after the fixed part */
    /* tcp->doff is in 32-bit words; minimum header is 5 * 4 = 20 bytes */
    if (tcp->doff < 5)
        return NULL;

    int tcp_hdr_len = tcp->doff * 4;
    if ((void *)tcp + tcp_hdr_len > (void *)tcp_end)
        return NULL;

    /* Options start after the fixed TCP header (20 bytes) */
    struct tcphdr *opt_start = (struct tcphdr *)((void *)tcp + 20);
    struct tcphdr *opt_end = (struct tcphdr *)((void *)tcp + tcp_hdr_len);

    /* Walk through options */
    while ((void *)opt_start + 2 <= (void *)opt_end) {
        __u8 kind = opt_start->th_off; /* reuse th_off as temporary, but actually kind is first byte */
        /* Actually th_off contains data offset; we need to read the kind byte */
        /* The first byte of options is at opt_start */
        if ((void *)opt_start >= (void *)opt_end)
            return NULL;
        kind = *(__u8 *)opt_start;

        if (kind == 0) {
            /* End of options list */
            return NULL;
        } else if (kind == 1) {
            /* NOP, 1 byte */
            opt_start = (struct tcphdr *)((void *)opt_start + 1);
        } else if (kind == 2) {
            /* MSS option: Kind=2, Length=4 (2 bytes kind + 2 bytes mss) */
            if ((void *)opt_start + 4 > (void *)opt_end)
                return NULL;
            /* Return pointer to the MSS value (bytes 2-3 of the option) */
            return (__u16 *)((void *)opt_start + 2);
        } else {
            /* Other option: skip Length bytes */
            if ((void *)opt_start + 1 > (void *)opt_end)
                return NULL;
            __u8 length = *(__u8 *)((void *)opt_start + 1);
            if (length < 2)
                return NULL; /* malformed */
            if ((void *)opt_start + length > (void *)opt_end)
                return NULL;
            opt_start = (struct tcphdr *)((void *)opt_start + length);
        }
    }
    return NULL;
}

/* Incrementally update TCP checksum by adding the delta */
static __always_inline void
update_tcp_checksum(struct tcphdr *tcp, __u16 delta)
{
    /* Current checksum */
    __sum16 *chk = &tcp->check;
    __u32 new = (long)*chk + delta;

    /* Fold carry */
    new = (new & 0xFFFF) + (new >> 16);
    new = (new & 0xFFFF) + (new >> 16);
    *chk = ~new;
}

int xdp_mss_clamp(struct xdp_md *xdpmd)
{
    /* Validate Ethernet frame */
    struct eth_hdr *eth = eth_hdr(xdpmd);
    if ((void *)(eth + 1) > (void *)xdpmd->data_end)
        return XDP_PASS;

    /* Validate IPv4 */
    struct iphdr *ip = ip_hdr(xdpmd);
    if (!ip)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Validate TCP */
    struct tcphdr *tcp = tcp_hdr(xdpmd);
    if (!tcp)
        return XDP_PASS;

    /* Filter: only TCP SYN packets (SYN flag set, ACK clear) */
    if (!(tcp->syn && !tcp->ack))
        return XDP_PASS;

    /* Parse TCP options to find MSS */
    struct tcphdr *tcp_end = (struct tcphdr *)((void *)tcp + xdpmd->data_end - (void *)tcp);
    __u16 *mss_opt = find_mss_option(tcp, tcp_end);
    if (!mss_opt)
        return XDP_PASS; /* No MSS option, pass unchanged */

    /* Check if requested MSS > 1300 (0x0514) */
    if (*mss_opt > 1300) {
        /* Clamp to 1300 */
        *mss_opt = 1300;

        /* Update TCP checksum incrementally.
         * The MSS field is 2 bytes; changing its value by delta updates checksum.
         * Delta = new_value - old_value (signed interpretation for addition) */
        __s16 old_val = * (__s16 *)mss_opt; /* read original as signed to compute delta */
        __s16 new_val = 1300;
        __s16 delta = new_val - old_val;

        /* The checksum is over pseudo-header + TCP header; adding delta to
         * the MSS field requires adding the same delta to the checksum.
         * We use the helper to fold and update. */
        update_tcp_checksum(tcp, delta);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
