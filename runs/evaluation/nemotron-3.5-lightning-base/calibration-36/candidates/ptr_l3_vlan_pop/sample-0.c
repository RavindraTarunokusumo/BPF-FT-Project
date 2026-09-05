/* ptr_l3_vlan_pop
 *
 * XDP program that removes exactly one 802.1Q VLAN header from single-tagged
 * Ethernet frames using the XDP head-adjustment mechanism.
 *
 * For single-tagged frames (eth->h_proto == bpf_htons(ETH_P_8021Q)):
 *   - Copy the encapsulated EtherType into the outer Ethernet header
 *   - Shift Ethernet destination and source MACs 4 bytes forward
 *   - Return XDP_PASS
 *
 * Pass untagged, double-tagged (QinQ), non-VLAN, and malformed frames
 * unchanged with XDP_PASS.
 *
 * GPL license
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/ctx.h>
#include <bpf/helpers.h>

SEC("xdp")
int xt_vlan_pop(struct xdp_md *ctx)
{
	void *data_end;
	void *data;
	struct eth_hdr *eth;
	u16 inner_etype;

	/* Obtain pointers to packet data boundaries */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* Verify Ethernet header fits within packet bounds */
	if (data + sizeof(struct eth_hdr) > data_end)
		return XDP_PASS;

	eth = data;

	/* Only process single-tagged frames: 802.1Q == 0x8100 */
	if (eth->h_proto != bpf_htons(ETH_P_8021Q))
		return XDP_PASS;

	/* Verify VLAN header fits within packet bounds (4 bytes after Ethernet header) */
	if (data + sizeof(struct eth_hdr) + VLAN_HLEN > data_end)
		return XDP_PASS;

	/* Extract the inner EtherType from the VLAN tag.
	 * The VLAN tag is 2 bytes TCI followed by 2 bytes EtherType.
	 * After the Ethernet header, the layout is: TCI (2 bytes) + inner EtherType (2 bytes).
	 * The inner EtherType pointer is at eth + 1 (first 2 bytes after eth header are TCI,
	 * next 2 bytes are the inner EtherType). */
	inner_etype = eth->h_proto; /* will be overwritten with inner value */

	/* The inner EtherType resides at (eth + 1) + 2 = eth + 3, but we can read it
	 * directly from the 4-byte VLAN tag area. The tag is stored as:
	 *   bytes[0..1] = TCI
	 *   bytes[2..3] = inner EtherType
	 * Since eth points to the Ethernet header, the inner EtherType is at
	 * (void *)(eth + 1) + 2, which is the third and fourth byte after eth.
	 * We cast the 4-byte VLAN area to access it. */
	{
		u16 __maybe_unused *vtc = data + sizeof(struct eth_hdr);
		/* vtc[0] = TCI, vtc[1] = inner EtherType */
		inner_etype = vtc[1];
	}

	/* Perform 4-byte head adjustment.
	 * bpf_xdp_adjust_head(ctx, 4) shifts the Ethernet header and MAC addresses
	 * 4 bytes forward, effectively removing the VLAN tag while preserving the
	 * encapsulated EtherType at the new outer header location.
	 * The XDP helper adjusts the data and data_end pointers accordingly. */
	bpf_xdp_adjust_head(ctx, 4);

	/* After adjustment, the Ethernet header has moved.
	 * The new eth pointer is data (which was shifted forward by 4 bytes
	 * internally by the helper, but we re-fetch for clarity). */
	eth = data;

	/* Restore the encapsulated EtherType into the outer Ethernet header.
	 * The inner EtherType we extracted earlier now becomes the outer
	 * Ethernet type, effectively "popping" the VLAN tag. */
	eth->h_proto = bpf_htons(inner_etype);

	/* Packet payload is preserved exactly: the data_end remains unchanged
	 * relative to the original packet, and the head adjustment only moved
	 * the start. The inner payload that was after the VLAN tag is now
	 * directly after the new outer header. */

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
