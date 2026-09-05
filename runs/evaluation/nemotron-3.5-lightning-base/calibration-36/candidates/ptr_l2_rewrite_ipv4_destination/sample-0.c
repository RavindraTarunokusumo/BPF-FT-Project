/* XDP program: rewrite IPv4 destination address to 203.0.113.9 and fix checksum */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/* Helper to load a 16-bit value from a pointer with bounds checking.
 * Returns 0 on failure, 1 on success and sets *val. */
static __always_inline int load_u16(const void *data, int off, __u16 *val)
{
    if (off + sizeof(__u16) > bpf_skb_load_bytes(data, off, val, sizeof(__u16)))
        return 0;
    return 1;
}

/* Helper to load a 32-bit value from a pointer with bounds checking. */
static __always_inline int load_u32(const void *data, int off, __u32 *val)
{
    if (off + sizeof(__u32) > bpf_skb_load_bytes(data, off, val, sizeof(__u32)))
        return 0;
    return 1;
}

/* Helper to store a 16-bit value with bounds checking. */
static __always_inline int store_u16(void *data, int off, __u16 val)
{
    if (bpf_skb_store_bytes(data, off, &val, sizeof(val), 0))
        return 0;
    return 1;
}

/* Helper to store a 32-bit value with bounds checking. */
static __always_inline int store_u32(void *data, int off, __u32 val)
{
    if (bpf_skb_store_bytes(data, off, &val, sizeof(val), 0))
        return 0;
    return 1;
}

/* IPv4 header checksum calculation (one's complement sum) */
static __always_inline __u16 ip_checksum(const void *data, int offset, int len)
{
    const __u16 *ptr = data + offset;
    __u32 sum = 0;
    int i, words = len / 2;
    __u16 tmp;

    for (i = 0; i < words; i++) {
        sum += ptr[i];
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    /* Handle odd byte */
    if (len % 2) {
        load_u16(ptr + words, 0, &tmp);
        sum += tmp;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    /* Fold to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

SEC("xdp")
int ptr_l2_rewrite_ipv4_dest(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;

    /* 1. Verify Ethernet frame bounds */
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    eth = data;

    /* 2. Verify EtherType == IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    /* 3. Verify IPv4 header bounds */
    ip = (struct iphdr *)(eth + 1);
    if ((void *)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    /* 4. Rewrite destination address to 203.0.113.9 */
    ip->daddr = bpf_htonl(0xCB007109); /* 203.0.113.9 in network byte order */

    /* 5. Recalculate IPv4 header checksum.
     *    The IPv4 header is at least 20 bytes (5 * 32-bit words).
     *    We compute the checksum over the first 20 bytes (5 words),
     *    clearing the existing checksum field first. */
    /* Zero out the current checksum */
    ip->check = 0;

    /* Compute checksum over the IPv4 header (20 bytes) */
    ip->check = ip_checksum(ip, 0, sizeof(struct iphdr));

    /* 6. Pass the (possibly modified) frame up the stack */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
