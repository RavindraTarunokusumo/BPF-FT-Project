/* XDP program: Decrement IPv4 TTL and recalculate checksum.
 * Drop if TTL <= 1, forward non-IP with XDP_PASS.
 *
 * Build: clang -target bpf -D__KERNEL__ -D__BPF_TRACING__ \
 *        -I /usr/src/linux-headers-$(uname -r)/include \
 *        -c xdp_ttl_dec.c -o xdp_ttl_dec.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* Helper: load 16-bit value in native byte order from a pointer */
static __always_inline __u16 load_u16(const void *ptr)
{
    return *(const __u16 *)ptr;
}

/* Helper: store 16-bit value */
static __always_inline void store_u16(void *ptr, __u16 val)
{
    *(__u16 *)ptr = val;
}

/* XDP entry point */
SEC("xdp")
int xdp_ttl_dec(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Confirm eth->h_proto == ETH_P_IP */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Drop packet if TTL is 1 or less */
    if (ip->ttl <= 1)
        return XDP_DROP;

    /* Decrement TTL */
    ip->ttl--;

    /* Recalculate IPv4 header checksum.
     * The checksum field is at offset 10 (ip_hl+version in first 4 bytes,
     * then tos, then total_len, then id, then frag_off, then ttl, then protocol,
     * then check).  We add the delta of the TTL byte change (0) and fold
     * the 16-bit one's complement sum over the header.
     * Since only ip->ttl changed (decrement by 1), the checksum must be
     * updated by adding 1 to the sum and folding.
     * Simpler approach: recompute over the entire header using a helper.
     */

    /* Fold and complement the 16-bit sum */
    __u32 csum = ip->check;          /* existing checksum (already one's complement) */
    /* Add the changed byte(s) – here only ttl changed, value delta = -1 -> +255 in unsigned */
    /* We'll just add 1 to the sum and fold; the true recompute is done below. */
    /* Actually, let's recompute the checksum over the IPv4 header correctly. */

    /* Zero out the checksum field temporarily */
    ip->check = 0;

    /* Pseudo-header checksum accumulation (IP header only, no pseudo-header) */
    /* The kernel helper csum_fold is not available in plain XDP, so we do it manually. */
    /* Sum all 16-bit words of the header */
    __u16 *ptr = (__u16 *)ip;
    int words = (ip->ihl * 4) / 2;   /* ihl is in 4-byte units */
    __u32 sum = 0;

    for (int i = 0; i < words; i++) {
        sum += *ptr++;
        /* Fold carry */
        if (sum > 0xFFFF)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* Add any remaining carry */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    /* One's complement */
    __u16 final_csum = ~sum;

    /* Write back the recalculated checksum */
    ip->check = final_csum;

    /* Return XDP_TX for forwarded packets */
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
