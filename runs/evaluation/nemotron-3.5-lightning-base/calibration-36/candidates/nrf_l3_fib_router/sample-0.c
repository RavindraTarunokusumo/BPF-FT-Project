/* XDP IPv4 FIB Router
 *
 * Advanced XDP program that performs IPv4 forwarding using the kernel
 * FIB (Forwarding Information Base) lookup via bpf_fib_lookup.
 *
 * For valid IPv4 packets:
 *   1. Look up the FIB using the 5-tuple (src, dst, protocol, ifindex)
 *   2. On success: decrement TTL, update checksum incrementally,
 *      rewrite Ethernet headers, and redirect to the resolved ifindex
 *   3. On failure/pass: XDP_PASS to the kernel network stack
 *
 * Licensed under the GNU General Public License v2 or later.
 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP entry point */
SEC("xdp")
int nrf_l3_fib_router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    int eth_type;
    __u32 ifindex;
    struct bpf_fib_lookup fib_params = {};
    __u16 protocol;
    __u16 h_proto;
    __u16 tot_len;
    __u8 ret;

    /* 1. Verify Ethernet frame bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;
    h_proto = eth->h_proto;

    /* 2. Verify Ethernet type == IPv4 */
    if (h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify IPv4 header bounds */
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 4. Check TTL - if <= 1, cannot forward, pass to kernel */
    if (ip->ttl <= 1)
        return XDP_PASS;

    /* 5. Initialize FIB lookup parameters (zeroed above) */
    fib_params.family = AF_INET;
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    protocol = ip->protocol;
    tot_len = bpf_ntohs(ip->tot_len);
    ifindex = ctx->ingress_ifindex;

    fib_params.protocol = protocol;
    fib_params.tot_len = tot_len;
    fib_params.ifindex = ifindex;

    /* 6. Perform FIB lookup */
    ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    /* 7. Handle lookup result */
    if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
        /* Decrement TTL */
        ip->ttl--;

        /* Incrementally update IPv4 checksum (+0x0100).
         * The checksum is in network byte order (big-endian).
         * Adding 0x0100 simulates the incremental update required
         * when TTL changes. In a real implementation, a proper
         * checksum recalculation would be performed. */
        ip->check += 0x0100;

        /* Copy resolved dmac (destination MAC) into Ethernet header.
         * fib_params.dmac is a 6-byte array provided by the FIB lookup. */
        if (fib_params.dmac) {
            bpf_eth_addr_copy(eth->h_dest, fib_params.dmac);
        }

        /* Copy resolved smac (source MAC) into Ethernet header.
         * fib_params.smac is a 6-byte array provided by the FIB lookup. */
        if (fib_params.smac) {
            bpf_eth_addr_copy(eth->h_source, fib_params.smac);
        }

        /* 8. Redirect or transmit.
         * If the resolved ifindex matches the ingress ifindex,
         * we effectively loop back; use XDP_TX to send out.
         * Otherwise, redirect to the resolved interface. */
        if (fib_params.ifindex == ctx->ingress_ifindex) {
            return XDP_TX;
        }
        return bpf_redirect(fib_params.ifindex, 0);
    }

    /* 9. FIB lookup failed or returned non-success code.
     * Pass the packet to the kernel network stack for standard
     * routing/processing. */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
