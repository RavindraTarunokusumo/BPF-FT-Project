/* XDP program: ptr_l2_decrement_ttl
 *
 * Purpose: Decrement the IPv4 TTL field when TTL > 1, update the IPv4 header
 *          checksum, and pass the packet. Drop if TTL <= 1.
 *
 * License: GPL
 * Entry point: SEC("xdp")
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/* Helper to safely access a field within a struct, checking bounds. */
static __always_inline void *ptr_load(void *ptr, int size, int *ret)
{
    if (ptr == NULL || size < 0) {
        *ret = -1;
        return NULL;
    }
    return ptr;
}

SEC("xdp")
int ptr_l2_decrement_ttl(struct xdp_md *ctx)
{
    void *data_end;
    void *data;
    struct eth_hdr *eth;
    struct iphdr *ip;
    __u16 h_proto;
    __u8 ttl;

    /* Obtain data and data_end pointers for bounds checking. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify we have enough room for an Ethernet header. */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Check EtherType for IPv4. */
    h_proto = eth->h_proto;
    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify we have enough room for an IPv4 header. */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);

    /* Verify IPv4 header is within bounds. */
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Read TTL. */
    ttl = ip->ttl;

    /* If TTL <= 1, drop the packet. */
    if (ttl <= 1)
        return XDP_DROP;

    /* Decrement TTL. */
    ip->ttl = ttl - 1;

    /* Update IPv4 header checksum.
     *
     * The IPv4 header checksum is the 16-bit one's complement of the one's
     * complement sum of all 16-bit words in the header.  For a single-byte
     * decrement we can increment the checksum by 1, wrapping around if it
     * crosses the 16-bit boundary.
     *
     *   new_check = old_check + 1
     *   if (new_check < old_check)  // overflow wrapped around
     *       new_check += 1;         // actually add the carry bit
     *
     * This is equivalent to:  check = (check + 1) & 0xFFFF;  but the
     * explicit form is used here to match the specification style.
     */
    {
        __wsum old_check = ip->check;
        __wsum new_check;

        /* Add 1 to the checksum. */
        new_check = old_check + bpf_htons(0x0100);

        /* If the addition wrapped around (carry out of the low 16 bits),
         * add the carry bit back into the sum. */
        if (new_check < old_check)
            new_check += 1;

        ip->check = new_check;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
