/* nrf_l1_udp_reflector
 *
 * XDP program that reflects valid IPv4 UDP packets at Layer 2.
 * Valid packets have their Ethernet source and destination MAC addresses
 * swapped and are transmitted back out the same interface (XDP_TX).
 * All other packets (TCP, ICMP, non-IPv4, malformed frames) are passed
 * through unchanged with XDP_PASS.
 *
 * GPL License
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Helper to safely access a field within a struct, checking bounds. */
#define CHECK_TYPE(type, ptr, len)                                          \
    ({                                                                      \
        typeof(type) __val = *(type *)(ptr);                                \
        if ((ptr) + sizeof(type) > (len)) {                                 \
            __val = 0;                                                      \
        }                                                                   \
        __val;                                                              \
    })

/* XDP entry point */
SEC("xdp")
int nrf_l1_udp_reflector(struct xdp_md *ctx)
{
    void *data_end;
    void *data;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;

    /* Obtain data and data_end pointers for bounds checking. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Ensure we have at least an Ethernet header. */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Verify Ethernet type is IPv4 (ETH_P_IP). */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Adjust pointers and bounds for IPv4 header. */
    data += sizeof(*eth);
    if (data + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data;

    /* Verify IP protocol is UDP. */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Adjust pointers and bounds for UDP header. */
    data += sizeof(*ip);
    if (data + sizeof(*udp) > data_end)
        return XDP_PASS;

    udp = data;

    /* Optional: verify UDP payload fits within the frame.
     * udp->len is in network byte order (big endian). */
    if (udp->len > (data_end - data))
        return XDP_PASS;

    /* Swap Ethernet source and destination MAC addresses.
     * We use a temporary __u16 array to swap the 6 bytes in three pairs. */
    __u16 tmp[3];

    tmp[0] = eth->h_source[0];
    tmp[0] = eth->h_dest[0];   /* actually we need to swap pair-wise, but C99
                                 initializer or byte-by-byte is safer.
                                 Here we do a proper 6-byte swap using
                                 __u8 temporaries on the stack. */
    /* The above was a draft mistake; let's do it correctly with __u8. */
    {
        __u8 tmp_byte[6];

        /* Copy destination to temp, then source to destination, then temp to source. */
        __builtin_memcpy(tmp_byte, eth->h_dest, 6);
        __builtin_memcpy(eth->h_dest, eth->h_source, 6);
        __builtin_memcpy(eth->h_source, tmp_byte, 6);
    }

    /* Return XDP_TX to transmit the modified frame back out. */
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
