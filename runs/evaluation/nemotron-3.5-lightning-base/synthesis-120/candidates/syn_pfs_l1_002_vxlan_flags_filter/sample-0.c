/* XDP program: VXLAN flags filter
 *
 * Inspects VXLAN traffic on UDP destination port 4789.
 * Parses the 8-byte VXLAN header and checks the 32-bit flags field.
 * The only valid flag in RFC 7348 is the I-bit (0x08000000 in network order / bit 27).
 * If any reserved flag bits are non-zero (flags & ~0x08000000 != 0), drop the packet.
 * Pass all valid VXLAN frames, non-VXLAN traffic, and malformed packets.
 *
 * Compilation: clang -target bpf -O2 -c vxlan_flags_filter.c -o vxlan_flags_filter.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* VXLAN header: 8 bytes following the UDP header */
struct vxlan_hdr {
    __be32	vxlan_flags;   /* bits 31-24: reserved, bit 27: I, bits 23-16: VNI most significant, bits 15-0: VNI least significant */
    __be16	vxlan_vni;     /* VXLAN Virtual Network Identifier (20 bits) */
} __attribute__((packed));

/* Helper: load a 32-bit value from a pointer, doing bounds checking via the verifier.
 * We use the bpf_load_bytes macro pattern implicitly by accessing struct fields
 * within verified bounds. For the flags field we do an explicit check. */

SEC("xdp")
int xdp_vxlan_flags_filter(struct xdp_md *ctx)
{
    void *data_end;
    void *data;

    /* Obtain the base pointers for the packet and end-of-packet check. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet header bounds. */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS; /* truncated Ethernet header */

    /* 2. Validate IPv4 protocol. Only process IPv4. */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS; /* non-IP traffic -> pass */

    /* 3. Validate IPv4 header bounds and extract IHL. */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS; /* truncated IPv4 header */

    /* ip->ihl is in 32-bit words; multiply by 4 to get bytes. */
    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return XDP_PASS; /* invalid IHL */

    if (data + sizeof(*eth) + ip_hdr_len > data_end)
        return XDP_PASS; /* IPv4 header extends beyond packet */

    /* 4. Verify UDP protocol. */
    /* ip->protocol is 1=ICMP, 6=TCP, 17=UDP. */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS; /* non-UDP IPv4 -> pass */

    /* 5. Validate UDP header bounds. */
    struct udphdr *udp = (struct udphdr *)(data + sizeof(*eth) + ip_hdr_len);
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*udp) > data_end)
        return XDP_PASS; /* truncated UDP header */

    /* 6. Verify UDP destination port is 4789. */
    if (udp->dest != htons(4789))
        return XDP_PASS; /* not VXLAN UDP port -> pass */

    /* 7. Validate VXLAN header bounds (8 bytes after UDP header). */
    struct vxlan_hdr *vxlan = (struct vxlan_hdr *)(udp + 1);
    if (data + sizeof(*eth) + ip_hdr_len + sizeof(*udp) + sizeof(*vxlan) > data_end)
        return XDP_PASS; /* truncated VXLAN header -> pass */

    /* 8. Check the VXLAN flags field.
     *    Valid flag: I-bit (0x08000000 in network byte order, bit 27).
     *    Reserved bits must be zero: flags & ~0x08000000 must be 0.
     *    Since flags is in network order, the I-bit is bit 27 from MSB.
     *    ~0x08000000 masks out the I-bit, leaving all other bits.
     *    If any of those bits are set, the packet has reserved flags non-zero -> drop.
     */
    __be32 flags = vxlan->vxlan_flags;
    if (flags & ~__constant_htons(0x0800)) {
        /* Wait: 0x08000000 is a 32-bit value. htons(0x0800) is 16-bit.
         * We need to compare with the 32-bit mask. Use __constant_cpu_to_be32 */
        return XDP_DROP;
    }

    /* 9. All checks passed: valid VXLAN frame with proper flags, or we passed earlier. */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
