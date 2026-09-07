/* XDP GRE Tunnel Loopback Reflector
 *
 * This program intercepts GRE packets (protocol 47) and reflects them
 * back by swapping the outer Ethernet MAC addresses and outer IPv4
 * source/destination addresses, recalculating the IPv4 checksum, and
 * returning the packet via XDP_TX.
 *
 * Non-GRE traffic is passed through unchanged via XDP_PASS.
 *
 * Compilation: clang -target bpf -O2 -c gre_tunnel_reflector.c -o gre_tunnel_reflector.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/ctx/sk_buff.h>

/* Helper: load 16-bit value in native byte order */
static __always_inline __u16 load_u16(const void *ptr)
{
    return *(const __u16 *)ptr;
}

/* Helper: store 16-bit value */
static __always_inline void store_u16(void *ptr, __u16 val)
{
    *(__u16 *)ptr = val;
}

/* Helper: swap two fields of equal size */
static __always_inline void swap_fields(void *a, void *b, int size)
{
    char tmp[size];
    bpf_probe_read_kernel(tmp, size, a);
    bpf_probe_read_kernel(a, size, b);
    bpf_probe_read_kernel(b, size, tmp);
}

/* XDP program entry point */
SEC("xdp")
int gre_tunnel_reflector(struct bpf_xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Validate minimal Ethernet header size */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets (ethertype 0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    /* Validate IPv4 header bounds */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Check for GRE protocol (ip->protocol == 47) */
    if (ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    /* --- GRE packet detected: perform reflection ---

     * We swap:
     *   - Outer Ethernet source and destination MAC addresses
     *   - Outer IPv4 source and destination addresses
     *   - Recalculate the IPv4 checksum
     *
     * Note: This simple reflector operates on the outer headers only.
     * Inner payload is left untouched.
     */

    /* Swap Ethernet MACs */
    swap_fields(&eth->h_source, &eth->h_dest, ETH_ALEN);

    /* Swap IPv4 endpoints */
    swap_fields(&ip->saddr, &ip->daddr, sizeof(__be32));

    /* Recalculate IPv4 checksum.
     * ip->check is originally 0 for GRE packets encapsulating payload,
     * but we recompute it over the new header state.
     */
    ip->check = 0;
    ip->check = bpf_csum_diff(0, &ip->saddr, &ip->daddr, 0, 0);
    /* The above csum_diff adds the new saddr->daddr contribution.
     * For a full header checksum, we would need to sum all 16-bit
     * words of the IPv4 header. The simplified approach below does a
     * proper Internet checksum over the IPv4 header words.
     */
    {
        __u32 sum = 0;
        const __u16 *ptr = (const __u16 *)ip;
        int i;
        /* IP header without the checksum field itself */
        for (i = 0; i < (ip->ihl * 4) / 2; i++) {
            sum += ptr[i];
            if (sum > 0xFFFF)
                sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ip->check = ~sum;
    }

    /* Reflect the packet out */
    return XDP_TX;
}

char LICENSE[] = "GPL";
