/* XDP program: Strip IPv4 options when ihl == 6 (24-byte header, 4 bytes of options).
 * Uses bpf_xdp_adjust_head to pop 4 bytes, restores Ethernet MACs,
 * updates ihl to 5, adjusts tot_len, and recomputes the IPv4 header checksum.
 * Packets with ihl == 5 are passed unchanged.
 * Always returns XDP_PASS.
 *
 * Compilation: clang -target bpf -O2 -c xdp_strip_opts.c -o xdp_strip_opts.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Helper: load a 16-bit value from a pointer with bounds checking.
 * Returns the value or -1 on failure (which we treat as packet drop/skip). */
static __always_inline __u16 load_u16(const void *ptr, int offset, int len)
{
    if (ptr == NULL || (void *)ptr + offset + 2 > (void *)((__u8 *)ptr + len))
        return -1;
    return bpf_ntohs(*(__be16 *)((__u8 *)ptr + offset));
}

/* Helper: store a 16-bit value at a pointer with bounds checking. */
static __always_inline void store_u16(void *ptr, int offset, __u16 val)
{
    if (ptr != NULL && (void *)ptr + offset + 2 <= (void *)((__u8 *)ptr + BPF_CORE_READ(ctx, data_end)))
        *(__be16 *)((__u8 *)ptr + offset) = bpf_hts(val);
}

struct xdp_md *xdp_entry(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet frame boundaries. */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate IPv4 protocol and header boundaries. */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (ip + 1 > (struct iphdr *)data_end)
        return XDP_PASS;

    /* 3. Verify ip->ihl == 6 (20 bytes base + 4 bytes options = 24-byte header). */
    if (ip->ihl != 6)
        return XDP_PASS;

    /* 4. Pop 4 option bytes using bpf_xdp_adjust_head.
     *    This shifts the payload forward by 4 bytes and reduces data_len.
     *    After adjustment, ip still points to the same base address,
     *    but the effective header length shrinks by 4 bytes. */
    bpf_xdp_adjust_head(ctx, 4);

    /* 5. Re-validate IPv4 header after adjustment.
     *    The ip pointer may now point past the new data_end if we are not careful,
     *    but adjust_head keeps the start of the packet at the same offset
     *    relative to the original data buffer, just moving the end.
     *    We re-check that ip + (5 * 4) <= data_end. */
    if (ip + 5 > (struct iphdr *)data_end)
        return XDP_PASS;

    /* 6. Restore Ethernet MAC addresses.
     *    adjust_head moves the entire packet forward (towards the adapter),
     *    which swaps the MACs in the buffer. We explicitly swap them back
     *    to maintain the original order as seen by the host. */
    __u8 tmp_mac[6];
    /* Save dst */
    bpf_memcpy(tmp_mac, eth->h_dest, 6, BPF_F_FAST);
    /* Save src */
    bpf_memcpy(eth->h_dest, eth->h_source, 6, BPF_F_FAST);
    /* Restore dst */
    bpf_memcpy(eth->h_source, tmp_mac, 6, BPF_F_FAST);

    /* 7. Set ip->ihl = 5 (20-byte header, no options). */
    ip->ihl = 5;

    /* 8. Update ip->tot_len.
     *    tot_len represents the total length of the IP packet (header + payload).
     *    adjust_head reduced the payload size by 4 bytes, so we must subtract 4
     *    from tot_len to keep the length consistent. */
    ip->tot_len = bpf_ntohs(bpf_ntohs(ip->tot_len) - 4);

    /* 9. Recompute the IPv4 header checksum.
     *    The checksum field is at offset 10 (2 bytes) in struct iphdr.
     *    We add 4 to the raw 16-bit value (since we removed 4 bytes of options
     *    and the header shrunk), then fold the carry and complement. */
    __u16 *check = &ip->check;
    *check = bpf_htons(bpf_ntohs(*check) + 4);

    /* 10. Return XDP_PASS as required. */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
