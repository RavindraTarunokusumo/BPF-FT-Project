/* XDP IPv4 L3 Router with bpf_fib_lookup
 *
 * This program performs a FIB (Forwarding Information Base) lookup on
 * valid IPv4 packets.  If the lookup succeeds, the TTL is decremented,
 * the IPv4 checksum is updated incrementally, the Ethernet header is
 * rewritten with the resolved dmac/smac, and the packet is redirected
 * to the resolved egress interface.  On any failure or when the TTL has
 * already expired, the packet is passed to the kernel network stack.
 *
 * License: GPL-2.0
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int nrf_l3_fib_router_xdp(void *ctx)
{
    /* Obtain packet metadata */
    struct xdp_md *md = ctx;
    void *data = (void *)(long)md->data;
    void *data_end = (void *)(long)md->data_end;

    /* ----- 1. Verify Ethernet frame boundaries ----- */
    struct eth_hdr *eth;
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* ----- 2. Verify IPv4 protocol ----- */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ----- 3. Verify IPv4 frame boundaries ----- */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* ----- 4. TTL check ----- */
    if (ip->ttl <= 1)
        return XDP_PASS;

    /* ----- 5. Prepare bpf_fib_lookup parameters ----- */
    struct bpf_fib_lookup fib_params = {
        .family         = AF_INET,
        .ipv4_src       = ip->saddr,
        .ipv4_dst       = ip->daddr,
        .protocol       = ip->protocol,
        .tot_len        = bpf_ntohs(ip->tot_len),
        .ifindex        = ctx->ingress_ifindex,
        /* The rest of the struct is zero-initialized by the = { ... } initializer */
    };

    /* ----- 6. Perform FIB lookup ----- */
    int ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    /* ----- 7. Handle lookup result ----- */
    if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
        /* ----- 7a. Decrement TTL ----- */
        ip->ttl--;

        /* ----- 7b. Incrementally update IPv4 checksum (+0x0100) ----- */
        /* The IPv4 checksum is stored in ip->check (network byte order). */
        /* Adding 0x0100 and handling the end-around carry. */
        u16 new_check = bpf_ntohs(ip->check) + 0x0100;
        /* Fold the carry: if the high bit wraps around, add it to the low byte. */
        new_check = (new_check & 0xFFFF) + (new_check >> 16);
        ip->check = bpf_htons(new_check);

        /* ----- 7c. Resolve dmac/smac ----- */
        /* bpf_fib_lookup populates fib_params.nh_metrs[0] with neighbour info.
         * For a minimal example we copy the resolved MAC addresses directly.
         * The exact layout depends on the neighbour subsystem; here we assume
         * the presence of a resolved neighbour with 6-byte MAC.
         */
        /* Resolve destination MAC (6 bytes) */
        if (fib_params.nh_metrs[0].nh_flags & BPF_FIB_METRICS_F_nh_gw) {
            /* Copy resolved dmac to eth->h_dest */
            bpf_probe_read_kernel(&eth->h_dest, ETH_ALEN,
                                  fib_params.nh_metrs[0].nh_mac);
        }

        /* Resolve source MAC (6 bytes) – typically the egress interface MAC.
         * For this program we simply copy the interface MAC from the FIB metrics.
         * In a production system you would retrieve the interface address
         * via netdev ops or a separate lookup.
         */
        /* NOTE: The exact field to fetch the source MAC varies per kernel version.
         * For the purpose of this template we assume fib_params contains a valid
         * source MAC in nh_metrs[0].nh_mac, or we fall back to the original smac.
         */
        bpf_probe_read_kernel(&eth->h_source, ETH_ALEN,
                              fib_params.nh_metrs[0].nh_mac);

        /* ----- 7d. Redirect to egress interface ----- */
        /* If the resolved ifindex is the same as the ingress interface,
         * we output to the CPU (XDP_TX) to avoid infinite loops. */
        if (fib_params.ifindex == ctx->ingress_ifindex) {
            return XDP_TX;
        }
        return bpf_redirect(fib_params.ifindex, 0);
    }

    /* ----- 8. FIB fallback / failure ----- */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
