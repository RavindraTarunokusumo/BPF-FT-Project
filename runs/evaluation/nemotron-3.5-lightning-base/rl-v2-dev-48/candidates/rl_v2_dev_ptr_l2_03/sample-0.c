#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

/* XDP program that remaps customer VLAN ID 120 to internal VLAN 220 in-place.
 * It modifies the TCI field preserving the priority bits and setting the VID to 220.
 * All packets are forwarded with XDP_PASS.
 */

SEC("xdp")
int remap_vlan_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct vlan_hdr *vlan;

    /* Verify Ethernet header bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Check for 802.1Q VLAN protocol */
    if (eth->h_proto != htons(ETH_P_8021Q))
        return XDP_PASS;

    /* Verify VLAN header bounds: eth + vlan_hdr must be within data_end */
    if (data + sizeof(*eth) + sizeof(*vlan) > data_end)
        return XDP_PASS;

    vlan = (struct vlan_hdr *)(eth + 1);

    /* Check if the encapsulated VLAN ID is 120 */
    /* vlan->h_vlan_TCI layout (big-endian network byte order):
     * bits 15-13: priority (3 bits)
     * bits 12-0:  VID (12 bits)
     * We need to extract the VID while preserving priority.
     *
     * Since h_vlan_TCI is in network byte order (big-endian),
     * the VID occupies the lower 12 bits (bits 0-11).
     * The priority occupies the upper 3 bits (bits 13-15).
     *
     * To remap VID 120 -> 220 while preserving priority:
     *   new_tci = (old_tci & 0xE000) | 220;
     * This works because:
     *   - old_tci & 0xE000 keeps the priority bits (13-15)
     *   - OR with 220 sets the VID field (0-11) to 220
     *   - The result is still in network byte order.
     */

    if (vlan->h_vlan_TCI & 0xFFF == 120) {
        /* Remap VID: preserve priority bits (13-15), set VID to 220 */
        vlan->h_vlan_TCI = (vlan->h_vlan_TCI & 0xE000) | 220;
    }

    /* Forward the packet unconditionally */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
