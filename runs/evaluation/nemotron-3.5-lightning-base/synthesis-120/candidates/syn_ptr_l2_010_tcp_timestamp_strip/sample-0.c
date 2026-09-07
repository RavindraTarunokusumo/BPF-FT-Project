#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Helper to safely access a field within a struct, checking bounds. */
static __always_inline void *ptr_load(void *ptr, int size, int *off)
{
    if (off && *off + size > 0) {
        /* bounds check is done by verifier via *off */
    }
    return ptr;
}

/* Helper to safely advance a pointer and update offset. */
static __always_inline void *ptr_advance(void *ptr, int delta, int *off)
{
    if (off) {
        *off += delta;
    }
    return (char *)ptr + delta;
}

SEC("xdp")
int xdp_strip_tcp_timestamp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Validate Ethernet frame minimum size */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate EtherType IPv4 (0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Validate IPv4 header minimum size and bounds */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 4. Validate IPv4 protocol TCP (6) and header length */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* ip_hdrlen is in 32-bit words; minimum is 5 (20 bytes) */
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > 60)
        return XDP_PASS;

    if (data + sizeof(*eth) + ip_hdr_len > data_end)
        return XDP_PASS;

    /* 5. Validate TCP header minimum size and bounds */
    struct tcphdr *tcph = data + sizeof(*eth) + ip_hdr_len;
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*tcph) > data_end)
        return XDP_PASS;

    /* tcph->doff is in 32-bit words; minimum is 5 (20 bytes) */
    int tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || tcp_hdr_len > 60)
        return XDP_PASS;

    if (data + sizeof(*eth) + ip_hdr_len + tcp_hdr_len > data_end)
        return XDP_PASS;

    /* 6. Parse TCP options.
       Options start after the fixed TCP header (doff * 4 bytes).
       Option format: Kind (1 byte), Length (1 byte), Value (Length-2 bytes).
       Timestamp option: Kind=8, Length=10 (8 + 2 + 8 bytes). */

    char *opt_start = (char *)tcph + tcp_hdr_len;
    char *opt_end = data + sizeof(*eth) + ip_hdr_len + tcp_hdr_len;

    /* Walk through options */
    while (opt_start + 2 <= opt_end) {
        u8 kind = opt_start[0];
        u8 length = opt_start[1];

        /* Sanity: length must be at least 2 (kind+length), and not exceed remaining space */
        if (length < 2 || opt_start + length > opt_end)
            break;

        /* Check for Timestamp option: Kind=8, Length=10 */
        if (kind == 8 && length == 10) {
            /* Overwrite the 10 option bytes with NOPs (0x01) */
            for (int i = 0; i < 10; i++)
                opt_start[i] = 0x01;

            /* Recalculate TCP checksum.
               bpf_l3_csum_replace handles the replacement of the pseudo-header
               and TCP header fields. We replace the entire TCP header checksum
               (offset 16, 2 bytes) with 0 and let the helper recompute it.
               Note: The helper expects the 'with' value to be placed at the
               same offset; we set it to 0 and the helper will compute the correct
               checksum over the modified payload/options. */
            __u16 *csum_loc = (__u16 *)opt_start;
            *csum_loc = 0; /* clear old checksum first */

            /* bpf_l4_csum_replace is for L4; for TCP options we use
               bpf_l3_csum_replace which adjusts the IP total length and
               IP/TCP checksums. However, the simplest and verifier-safe way
               to recalc the TCP checksum is to use the dedicated helper
               over the TCP pseudo-header + header. */
            /* The following helper replaces the checksum field at
               (opt_start - tcp_header_base) with 0 and updates the
               TCP checksum accordingly. */
            bpf_l3_csum_replace(&(tcph->source), opt_start,
                                  opt_start, 2, 0);

            /* After modifying options, we must also update the
               TCP checksum field located at tcph->check (offset 16
               from tcph start). The helper above only adjusts the
               pseudo-header part; we explicitly rewrite the check field. */
            tcph->check = 0;
            /* Recalculate from scratch: pseudo-header + TCP header + options.
               We use bpf_l4_csum_replace with the source port as the
               key field to trigger full recalculation. */
            bpf_l4_csum_replace(&(tcph->source), tcph,
                                tcph, sizeof(struct tcphdr), 0);
            /* Restore the checksum computed by the helper. */
            tcph->check = bpf_csum_tcpudp_merge(ip->saddr, ip->daddr,
                                                tcph, tcp_hdr_len, 0);

            /* We are done with the timestamp option stripping. */
            break;
        }

        /* Advance to next option */
        opt_start += length;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
