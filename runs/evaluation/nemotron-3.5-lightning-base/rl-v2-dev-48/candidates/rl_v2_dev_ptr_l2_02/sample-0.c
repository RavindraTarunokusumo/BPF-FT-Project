#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

/* XDP program that retags ingress frames from VLAN 110 to staging VLAN 210 in-place.
 * Modifies the TCI field preserving priority bits and setting VID to 210.
 * Forwards all packets with XDP_PASS.
 */

SEC("xdp")
int xdp_vlan_retag(struct xdp_md *ctx)
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

	/* Verify VLAN header bounds: eth + 1 vlan tag */
	if (data + sizeof(*eth) + sizeof(*vlan) > data_end)
		return XDP_PASS;

	vlan = (struct vlan_hdr *)(eth + 1);

	/* Check if the inner VLAN ID is 110 */
	/* vlan_id is stored in the lower 12 bits of h_vlan_TCI */
	if (vlan->h_vlan_TCI & VLAN_VID_MASK) {
		uint16_t vid = vlan_ntoh(vlan->h_vlan_TCI) & VLAN_VID_MASK;
		if (vid != 110)
			return XDP_PASS;
	} else {
		/* No VLAN tag present (should not happen if h_proto == ETH_P_8021Q),
		 * but handle gracefully */
		return XDP_PASS;
	}

	/* Retag in-place: preserve priority bits (bits 13-15),
	 * set VID to 210 */
	/* Clear VID bits (lower 12 bits) and set new VID 210 */
	uint16_t new_tci = (vlan->h_vlan_TCI & ~VLAN_VID_MASK) | cpu_to_vlan(210);

	vlan->h_vlan_TCI = new_tci;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
