#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

/* XDP program that reassigns virtual network identifier from VLAN 130 to service VLAN 230 in-place.
 * Modifies the TCI field preserving priority bits and setting VID to 230.
 * Forwards all packets with XDP_PASS.
 */

SEC("xdp")
int xdp_vlan_reassign(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct vlan_hdr *vlan;

	/* Verify Ethernet header bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* Check if the Ethernet payload is 802.1Q VLAN tagged */
	if (eth->h_proto != htons(ETH_P_8021Q))
		return XDP_PASS;

	/* Verify VLAN header bounds: eth + vlan_hdr must be within data_end */
	if (data + sizeof(*eth) + sizeof(*vlan) > data_end)
		return XDP_PASS;

	vlan = (struct vlan_hdr *)(eth + 1);

	/* Check if the VLAN ID is 130 */
	if (vlan->h_vlan_TCI & htons(VLAN_VID_MASK)) {
		/* Extract the VID from the current TCI */
		__be16 current_vid = vlan->h_vlan_TCI & htons(VLAN_VID_MASK);

		if (current_vid == htons(130)) {
			/* Preserve priority bits (PCI: 3 bits at top of TCI)
			 * and replace VID with 230 while keeping the CFI bit (bit 13)
			 * and the existing priority bits.
			 *
			 * TCI layout (16 bits):
			 * [15:13] = Priority (3 bits)
			 * [12]    = CFI/DEI
			 * [11:0]  = VID (12 bits)
			 *
			 * To set VID to 230 (0x00E6) while preserving priority:
			 * new_tci = (old_tci & 0xE000) | htons(230)
			 * This preserves bits 15:13 (priority) and bit 12 (CFI),
			 * and sets bits 11:0 to 230.
			 */
			__be16 new_tci = (vlan->h_vlan_TCI & htons(0xE000)) | htons(230);

			/* Write the new TCI in-place */
			vlan->h_vlan_TCI = new_tci;
		}
	}

	/* Forward all packets unconditionally */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
