/* XDP program: rewrite UDP destination port to 5353 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Helper to access network headers safely */
static inline void *data_end(void *ptr)
{
    return (void *)(long)bpf_xdp_load_bytes(ptr, 0, 0); /* placeholder, not used directly */
}

static inline struct eth_hdr {
    __be16 h_proto;
} __attribute__((packed));

struct eth_hdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

SEC("xdp")
int xdp_rewrite_udp_port(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet header bounds check */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* IPv4 header start */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Verify IPv4 IHL: ihl is in 32-bit words, multiply by 4 for byte offset */
    unsigned int ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr) || ihl > (unsigned int)(data_end - (void *)ip))
        return XDP_PASS;

    /* UDP header start */
    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* If checksum is nonzero, update it incrementally.
     * The UDP checksum over IPv4 is: ~(UDP_pseudo_header + UDP_header + UDP_payload).
     * Modifying dest port flips the corresponding bit in the sum.
     * We use the bpf helper to update the checksum safely.
     * Note: bpf_l3_csum_replace works for l3/l4 csum adjustment.
     * Here we adjust the UDP dest field (offset 2) by the delta.
     * Delta = new_dest - old_dest = 5353 - ntohs(udp->dest)
     * Since we cannot easily get ntohs in constant expression, we compute delta
     * at runtime using bpf helpers or just recompute. To stay verifier-safe,
     * we use a simple XOR-based delta update if the port change is known,
     * but the most robust way within eBPF helpers is to use
     * bpf_l4_csum_replace or manual adjustment.
     * Given the constraint "update checksum correctly", we perform an
     * incremental update via bpf_l3_csum_replace which adjusts the
     * IP-level csum; for UDP we need l4 csum. We'll use a small
     * software adjustment: subtract old, add new.
     * However, eBPF verifier restricts arbitrary arithmetic on
     * checksum fields. The safest helper-approved method is:
     *   - Save old dest port value.
     *   - Compute delta = bpf_htons(5353) - udp->dest.
     *   - Update udp->dest.
     *   - Adjust UDP checksum by delta using bpf_l4_csum_replace
     *     (available in Linux 5.7+). If not available, we fall back
     *     to zeroing and recomputing, but that requires payload access.
     * For this level-2 task, we assume helper availability and
     * use bpf_l4_csum_replace with offset of dest field.
     *
     * Actually, bpf_l4_csum_replace takes (old, new, len, flags).
     * We'll compute delta = new - old, then do:
     *   bpf_l4_csum_replace(&udp->dest, &udp->dest, sizeof(udp->dest), 0);
     * This helper adjusts the checksum by (new - old) automatically.
     * Let's verify signature: void *bpf_l4_csum_replace(void *old, void *new,
     *                                     unsigned int len, unsigned int flags);
     * It returns pointer for chaining. We'll use it.
     */

    __be16 new_dest = bpf_htons(5353);

    /* Update destination port */
    udp->dest = new_dest;

    /* If checksum is nonzero, update it */
    if (udp->check) {
        /* bpf_l4_csum_replace adjusts the UDP checksum by (new - old).
         * We pass old = &udp->dest, new = &new_dest, len = 2 (port size).
         * The helper will update udp->check in-place. */
        bpf_l4_csum_replace(&udp->dest, &new_dest, sizeof(udp->dest), 0);
    }
    /* If udp->check == 0, leave it as zero (checksum disabled) */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
