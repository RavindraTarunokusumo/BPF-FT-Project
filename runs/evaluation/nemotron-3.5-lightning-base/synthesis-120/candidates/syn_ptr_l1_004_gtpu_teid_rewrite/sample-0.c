#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/ctx/sk_buff.h>
#include <bpf_endian.h>

/* GTP-U header definition (RFC 2637 / 4960).
 * The TEI field is 32-bit aligned and located at offset 8 from the start
 * of the GTP header. The first 8 bytes are the standard header:
 *   Version (1) | PT (3) | Reserved (1) | Length (1) | TEID (3) | ...
 * However, for the purpose of this level-1 task we treat the TEID as a
 * 32-bit value starting at offset 8 from the GTP header base.
 */
struct gtpuhdr {
    __be16  flags_and_seq_hi; /* version|pt|reserved|length, seq high */
    __be32  teid;             /* Tunnel Endpoint Identifier */
    /* optional: next header, payload length, etc. */
};

static __always_inline struct gtpuhdr *gtp_hdr(struct xdp_md *ctx)
{
    void *data   = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet header */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return NULL;

    /* IPv4 check */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return NULL;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return NULL;

    /* Must be UDP */
    if (ip->protocol != IPPROTO_UDP)
        return NULL;

    /* UDP header */
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return NULL;

    /* Verify UDP destination port is GTP-U (2152) */
    if (udp->dest != bpf_htons(2152))
        return NULL;

    /* GTP-U header starts right after UDP header.
     * Minimum GTP header is 8 bytes (octet 0-7). We need at least
     * 8 bytes to read the TEID field.
     */
    struct gtpuhdr *gtp = (struct gtpuhdr *)(udp + 1);
    if ((void *)(gtp + 1) > data_end)
        return NULL;

    /* Quick check: the first two bytes of GTP header should contain
     * version=1 and PT=0x0 (or appropriate). For a level-1 program we
     * accept any packet that has the right UDP port and sufficient
     * length; the real validation of the version field is omitted here
     * to keep the program simple and verifier-safe.
     */
    return gtp;
}

SEC("xdp")
int xdp_gtp_teid_rewrite(struct xdp_md *ctx)
{
    struct gtpuhdr *gtp = gtp_hdr(ctx);
    if (!gtp)
        return XDP_PASS; /* not a GTP-U packet – pass through */

    /* Rewrite the 32-bit TEID to the fixed value in network byte order. */
    gtp->teid = bpf_htonl(0x11223344);

    return XDP_PASS;
}

char LICENSE[] = "GPL";
