/**
 * nrf_l2_configured_redirect
 * Category: network_routing_forwarding
 * Difficulty: level_2
 *
 * XDP program that redirects valid Ethernet frames based on a configured
 * forwarding interface index stored in a BPF array map.
 *
 * Licensed under the GNU General Public License v2 or later.
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

/* Map definition:
 * Type: BPF_MAP_TYPE_ARRAY
 * Key: __u32 (index 0)
 * Val: __u32 (interface index)
 * Max entries: 1
 */
SEC("xdp")
int nrf_l2_configured_redirect(struct xdp_md *ctx)
{
    void *data_end;
    void *data;
    struct eth_hdr *eth;
    __u32 ifindex = 0;
    __u32 *p_ifindex;

    /* Retrieve the size of the packet data available to the XDP program. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Check for minimum Ethernet frame size (14 bytes for header).
     * Frames smaller than this are considered malformed/runt frames. */
    if (data + sizeof(struct eth_hdr) > data_end)
        return XDP_PASS;

    /* Pointer to the Ethernet header. */
    eth = data;

    /* Verify that the Ethernet header does not extend beyond the packet bounds. */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Lookup the forwarding interface index from the map.
     * Key 0 is used to store the configured egress interface. */
    p_ifindex = bpf_map_lookup_elem(forwarding_config, &ifindex);
    if (!p_ifindex)
        return XDP_ABORTED;

    /* Policy:
     * - If the mapped ifindex is 0 (unset/unset default), abort.
     * - If the mapped ifindex > 0, redirect the frame to that interface.
     */
    if (*p_ifindex == 0)
        return XDP_ABORTED;

    /* Redirect the frame to the configured interface index.
     * The second argument (0) is the flags parameter; 0 means use default behavior. */
    return bpf_redirect(*p_ifindex, 0);
}

/* Defines the BPF array map used for forwarding configuration.
 * Key: __u32 (index 0)
 * Val: __u32 (interface index)
 * Max entries: 1
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(val, __u32);
} forwarding_config SEC(".maps");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel XDP System");
MODULE_DESCRIPTION("L2 configured redirect XDP program");
