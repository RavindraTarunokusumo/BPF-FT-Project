/* XDP GTP-U Reflector
 * Inspects GTP-U traffic (UDP dst port 2152).
 * If gtp->teid == 0x12345678, reflects the frame with swapped MACs/IPs/ports.
 * Otherwise passes the frame.
 *
 * Compilation: clang -target bpf -O2 -c reflector.c -o reflector.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* GTP-U header definition (minimal, without optional IE fields)
 * Standard GTP-U header: 8 bytes
 *   - Version (3 bits) + PT (1 bit) + Reserved (1 bit) + S (1 bit) + N-P (1 bit) + E (1 bit) + Spare (1 bit) = 1 byte
 *   - Message Type (1 byte)
 *   - Length (2 bytes, network byte order)
 *   - TEID (4 bytes)
 */
struct gtpuhdr {
    __u8  version_pt;
    __u8  message_type;
    __be16 length;
    __be32 teid;
};

/* XDP program entry point */
SEC("xdp")
int xdp_gtpu_reflector(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet frame minimum size */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate IPv4 protocol */
    /* Check for IPv4 (0x0800) - we only handle IPv4; skip non-IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Validate IPv4 header bounds */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify IPv4 version (must be 4) */
    if (ip->version != 4)
        return XDP_PASS;

    /* 4. Validate UDP payload bounds */
    /* UDP header is always 8 bytes; total UDP length includes header */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* 5. Verify UDP destination port is 2152 (GTP-U well-known port) */
    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    /* 6. Validate GTP-U header bounds */
    struct gtpuhdr *gtp = (void *)udp + sizeof(*udp);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*gtp) > data_end)
        return XDP_PASS;

    /* 7. Verify GTP-U TEID matches 0x12345678 (host order) */
    /* gtp->teid is network byte order (__be32), so compare with bpf_htonl() */
    if (gtp->teid != bpf_htonl(0x12345678))
        return XDP_PASS;

    /* ---- Matching TEID: Perform reflection with swaps ---- */

    /* 8. Swap outer Ethernet MAC addresses */
    /* eth->h_source is the outer src MAC, eth->h_dest is the outer dst MAC */
    __u64 tmp_mac = eth->h_source.addr_bytes[0];
    /* Simple byte swap of the 6-byte MAC using 64-bit rotation trick:
     * We swap the first 3 bytes with the last 3 bytes.
     * Using a temporary 64-bit load/store is safe as alignment is usually OK
     * for XDP programs when accessing within the frame buffer.
     * However, to be strictly verifier-safe, we do byte-wise swap.
     */
    __u8 mac_tmp[6];
    bpf_probe_read_kernel(mac_tmp, sizeof(mac_tmp), &eth->h_source);
    bpf_probe_read_kernel(&eth->h_source, sizeof(mac_tmp), mac_tmp);
    bpf_probe_read_kernel(&eth->h_dest, sizeof(mac_tmp), &mac_tmp[3]);
    bpf_probe_read_kernel(&mac_tmp[3], sizeof(mac_tmp) - 3, &eth->h_dest);
    /* Actually, simpler: just swap the whole 6-byte arrays via memmove semantics
     * using helper functions if available, but here we use direct byte copy.
     * Since XDP verifier allows direct struct member access within bounds,
     * we can swap using a local temporary on the stack.
     */
    {
        __u8 tmp[6];
        bpf_lsm_memcpy_from_dev(mac_tmp, &eth->h_source, 6); /* placeholder, will use raw access */
        /* The verifier prefers explicit byte access; however, for brevity and
         * common XDP patterns, we use the following idiom which the verifier
         * typically accepts if bounds are checked. We'll use a manual swap:
         */
    }

    /* Manual 6-byte MAC swap to guarantee verifier safety */
    {
        __u8 s[6], d[6];
        int i;
        for (i = 0; i < 6; i++) {
            s[i] = eth->h_source.addr[i];
            d[i] = eth->h_dest.addr[i];
        }
        for (i = 0; i < 6; i++) {
            eth->h_source.addr[i] = d[i];
            eth->h_dest.addr[i] = s[i];
        }
    }

    /* 9. Swap IPv4 source and destination addresses */
    {
        __u32 s = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = s;
    }

    /* 10. Swap UDP source and destination ports */
    {
        __u16 s = udp->source;
        udp->source = udp->dest;
        udp->dest = s;
    }

    /* 11. Recalculate IPv4 checksum */
    /* ip_fast_csum is a macro that recalculates the header checksum
     * assuming the IP header is in native byte order for the first
     * (ihl * 4) bytes and the protocol/ttl fields are at the end.
     * Since we swapped saddr/daddr, we must recompute.
     * Note: ip_fast_csum works on the struct iphdr in memory.
     */
    ip->check = 0;
    ip->check = ip_fast_csum((__be32 *)ip, ip->ihl);

    /* 12. Reflect the frame via XDP_TX */
    /* XDP_TX sends the packet out the physical interface.
     * The packet buffer remains modified; the driver will transmit it.
     * We must ensure we do not exceed the frame size, but since we only
     * swapped fields within the existing buffer, it is safe.
     */
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
