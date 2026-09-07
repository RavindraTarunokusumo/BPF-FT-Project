/* XDP program: GENEVE VNI filter
 * Drops UDP packets on port 6081 (GENEVE) where the 24-bit VNI equals 0x001234
 * Passes all other traffic
 *
 * Compilation: clang -target bpf -O2 -c geneve_vni_filter.c -o geneve_vni_filter.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* GENEVE header definition (RFC 8604)
 * The header is 8 bytes minimum, but can have options.
 * We only parse the fixed base header.
 */
struct genevehdr {
    __be32 flags_proto;
    __be32 vni;
    __be16 protocol;
    __be16 vni_len;
    /* followed by options */
} __attribute__((packed));

/* Flags definitions for GENEVE */
#define GENEVE_FLAG_C (1 << 31) /* Checksum present */
#define GENEVE_FLAG_K (1 << 30) /* Key present */
#define GENEVE_FLAG_R (1 << 29) /* Recursion */
#define GENEVE_FLAG_P (1 << 28) /* Protocol */

/* XDP program entry point */
SEC("xdp")
int geneve_vni_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet header bounds */
    struct eth_hdr *eth;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;
    /* Check for IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 2. Validate IPv4 header bounds (supporting variable IHL) */
    struct iphdr *ip;
    /* iphdr starts after eth_hdr */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);
    /* Validate IHL: minimum 5 dwords (20 bytes), IHL is in 32-bit words */
    if (ip->ihl < 5)
        return XDP_PASS;
    /* Calculate IPv4 header end */
    if (data + sizeof(*eth) + (ip->ihl * 4) > data_end)
        return XDP_PASS;

    /* Check protocol == UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 3. Validate UDP header bounds and check dest port 6081 */
    struct udphdr *udp;
    /* UDP header starts after IPv4 header */
    if (data + sizeof(*eth) + (ip->ihl * 4) + sizeof(*udp) > data_end)
        return XDP_PASS;

    udp = data + sizeof(*eth) + (ip->ihl * 4);
    if (udp->dest != bpf_htons(6081))
        return XDP_PASS; /* Not a GENEVE packet, pass it */

    /* 4. Validate GENEVE header bounds */
    /* GENEVE base header is 8 bytes: flags_proto(4) + vni(4) */
    struct genevehdr *gen;
    if (data + sizeof(*eth) + (ip->ihl * 4) + sizeof(*udp) + sizeof(*gen) > data_end)
        return XDP_PASS; /* truncated GENEVE header */

    gen = data + sizeof(*eth) + (ip->ihl * 4) + sizeof(*udp);

    /* Verify GENEVE flags: must have Protocol bit (P) set and Key bit (K) cleared
     * for standard encapsulation. We check the flags_proto field.
     * bits 31:28 are flags, bit 28 is P (Protocol), bit 29 is R, bit 30 is K, bit 31 is C.
     * For a valid GENEVE packet with protocol field present: flags should have bit 28 set,
     * and bit 30 (K) should be 0. However, for simplicity and robustness, we just
     * verify the magic value in flags_proto indicates GENEVE.
     * GENEVE magic: 0x6969 (in network byte order, stored as __be32)
     * Actually, the Protocol field is at bits 27:0 of flags_proto if P=1.
     * Let's just check the VNI field and proceed; if it's not GENEVE, the VNI check
     * will just pass through.
     */

    /* 5. Extract 24-bit VNI from gen->vni[0..2] and drop if 0x001234
     * The VNI is stored in the upper 24 bits of the 32-bit vni field.
     * gen->vni is __be32. The VNI occupies bits 31:8.
     * We need to extract the top 24 bits.
     */
    __be32 vni_be = gen->vni;
    __u32 vni_host = bpf_ntohl(vni_be);
    /* Shift right 8 to get the 24-bit VNI value */
    __u32 vni_24 = vni_host >> 8;

    if (vni_24 == 0x001234) {
        /* Drop the packet */
        return XDP_DROP;
    }

    /* 6. Pass all other GENEVE VNIs, non-GENEVE UDP packets, etc. */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
