/* XDP hairpin reflection: swap TCP source/dest ports on IPv4 TCP packets.
 * All other packets are passed through.
 *
 * Compilation:  clang -target bpf -O2 -c hairpin.c -o hairpin.o
 * Load:         ip link set dev <if> xdp obj hairpin.o sec hairpin
 * Unload:       ip link set dev <if> xdp off
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Helper to safely load a 16-bit value from a pointer within data_end */
static __always_inline __u16 load_u16(const void *ptr)
{
    return *(const __u16 *)ptr;
}

static __always_inline __u16 read_uh(const void *ptr)
{
    return *(const __u16 *)ptr;
}

static __always_inline __u16 swap_u16(__u16 val)
{
    return ((val >> 8) & 0xFF) | ((val & 0xFF) << 8);
}

SEC("xdp")
int hairpin_xdp(struct xdp_md *md)
{
    void *data_end;
    void *data;

    data = (void *)(long)md->data;
    data_end = (void *)(long)md->data_end;

    /* 1. Verify Ethernet header bounds */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* 2. Confirm EtherType == IPv4 */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify IPv4 header bounds.
     *    ip->ihl is in 32-bit words; multiply by 4 to get byte count. */
    if (data + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);

    /* 4. Validate IPv4 header length (ihl * 4) */
    if (ip->ihl < 5 || (void *)(ip + ip->ihl) > data_end)
        return XDP_PASS;

    /* 5. Confirm IP protocol == TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 6. Verify TCP header bounds */
    /* tcp header starts after iphdr; iphdr length is ip->ihl * 4 bytes */
    void *tcp_start = (void *)ip + ip->ihl * 4;

    if (tcp_start + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = tcp_start;

    /* 7. Swap TCP source and destination ports in-place */
    __u16 tmp = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp;

    /* 8. Return XDP_TX to reflect the packet back out the same interface */
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
