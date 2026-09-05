/* XDP program: hairpin incoming TCP sessions by reversing source and destination port numbers.
 * Forward all other packets with XDP_PASS.
 *
 * Compilation: clang -target bpf -O2 -c hairpin_tcp.c -o hairpin_tcp.o
 * License: GPL
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Helper macro to safely load a 16-bit value from a pointer within the packet buffer.
 * Returns 0 on success, -1 on failure (out of bounds). */
#define LOAD_U16(ptr) ({ \
    u16 __val = 0; \
    if ((void *)(ptr) + sizeof(__val) > data_end) { \
        __val = -1; \
    } else { \
        __val = bpf_ntohs(*(u16 *)(ptr)); \
    } \
    __val; \
})

/* Helper macro to safely load a 32-bit value from a pointer within the packet buffer.
 * Returns 0 on success, -1 on failure (out of bounds). */
#define LOAD_U32(ptr) ({ \
    u32 __val = 0; \
    if ((void *)(ptr) + sizeof(__val) > data_end) { \
        __val = -1; \
    } else { \
        __val = bpf_ntohl(*(u32 *)(ptr)); \
    } \
    __val; \
})

SEC("xdp")
int hairpin_tcp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 2. Confirm eth->h_proto == ETH_P_IP (0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify IPv4 header bounds and extract IPv4 header */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 4. Safely validate variable IPv4 header length (ihl * 4) */
    u32 iphdr_len = (u32)ip->ihl * 4;
    if (iphdr_len < sizeof(struct iphdr) || iphdr_len > (data_end - (void *)ip))
        return XDP_PASS;

    /* 5. Confirm ip->protocol == IPPROTO_TCP (6) */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 6. Verify TCP header bounds using the validated IPv4 header length */
    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + iphdr_len);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* 7. Safely swap tcp->source and tcp->dest in-place */
    u16 src_port = LOAD_U16(&tcp->source);
    u16 dst_port = LOAD_U16(&tcp->dest);

    if (src_port != (u16)-1 && dst_port != (u16)-1) {
        tcp->source = dst_port;
        tcp->dest   = src_port;
    }

    /* 8. Return XDP_TX for reflected packets, XDP_PASS for other protocols */
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
