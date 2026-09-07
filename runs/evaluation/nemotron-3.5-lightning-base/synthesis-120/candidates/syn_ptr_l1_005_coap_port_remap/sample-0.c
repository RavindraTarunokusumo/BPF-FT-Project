/* XDP program: CoAP destination port remap from 5683 to 5684
 *
 * Inspects IPv4 UDP traffic targeting CoAP destination port 5683.
 * Rewrites destination port to 5684 and incrementally updates
 * the UDP checksum if non-zero.
 *
 * Returns XDP_PASS in all cases.
 *
 * Compilation:  clang -target bpf -O2 -c xdp_coap_remap.c -o xdp_coap_remap.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Helper: load 16-bit value in native byte order from given offset */
static __always_inline __u16 load_u16(const void *ptr)
{
    return *(const __u16 *)ptr;
}

/* Helper: store 16-bit value in native byte order at given offset */
static __always_inline void store_u16(void *ptr, __u16 val)
{
    *(__u16 *)ptr = val;
}

SEC("xdp")
int xdp_coap_port_remap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Validate Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Validate IPv4 protocol */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Must be UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Validate UDP header bounds */
    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* Check destination port 5683 (CoAP) */
    __u16 dest = load_u16(&udp->dest);
    if (dest != bpf_htons(5683))
        return XDP_PASS;

    /* Rewrite destination port to 5684 */
    store_u16(&udp->dest, bpf_htons(5684));

    /* Incrementally update UDP checksum if non-zero */
    if (udp->check) {
        /* CoAP port difference: 5684 - 5683 = 1 */
        __u16 diff = bpf_htons(1); /* positive difference */

        /* Add the 16-bit difference to the checksum */
        __u32 csum = (__u32)udp->check;
        csum += (unsigned int)diff;

        /* Fold carry into lower 16 bits */
        csum = (csum & 0xFFFF) + (csum >> 16);

        /* Add carry if any */
        if (csum > 0xFFFF)
            csum -= 0xFFFF;

        udp->check = (__sum16)csum;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
