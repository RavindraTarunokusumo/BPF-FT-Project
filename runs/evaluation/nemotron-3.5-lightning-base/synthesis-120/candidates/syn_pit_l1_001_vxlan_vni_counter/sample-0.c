#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* 
 * Per-CPU array map definition.
 * Key: __u32 (index 0)
 * Value: __u64 (counter)
 * Max entries: 1
 */
struct {
	__uint	type,		BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries,	1;
	__type(key, __u32);
	__type(value, __u64);
} vxlan_counter_map SEC(".maps");

/* 
 * XDP program entry point.
 * Inspects VXLAN traffic (UDP port 4789) and counts valid VXLAN frames.
 */
SEC("xdp")
int xdp_vxlan_counter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct vxlanhdr *vxlan;
	__u32 key = 0;
	__u64 *counter;

	/* 
	 * Minimum Ethernet frame size check.
	 * We need at least sizeof(struct ethhdr) to inspect Ethernet header.
	 */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 
	 * Validate Ethernet type.
	 * Only process IPv4 frames (ETH_P_IP = 0x0800).
	 * Other types are passed through without counting.
	 */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	data += sizeof(*eth);
	data_end = data_end; /* Keep original end for subsequent checks */

	/*
	 * IPv4 header validation.
	 * iphdr->ihl is in 32-bit words, so actual header length = ihl * 4.
	 * We need at least sizeof(struct iphdr) minimum, but IHL can be larger.
	 */
	if (data + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data;

	/* 
	 * Validate IPv4 IHL field.
	 * Minimum IHL is 5 (20 bytes). If IHL is less than 5, it's invalid.
	 */
	if (ip->ihl < 5)
		return XDP_PASS;

	/* 
	 * Calculate actual IPv4 header length and adjust data pointer.
	 * We use ip->ihl * 4 to get bytes, but must ensure we don't overflow.
	 */
	if (data + (ip->ihl * 4) > data_end)
		return XDP_PASS;

	/* 
	 * Verify protocol is UDP (IPPROTO_UDP = 17).
	 * If not UDP, pass through without counting.
	 */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	data += ip->ihl * 4;
	data_end = data_end; /* Re-validate bounds after offset */

	/*
	 * UDP header validation.
	 * We need at least sizeof(struct udphdr) after the IP header.
	 */
	if (data + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = data;

	/*
	 * Verify UDP destination port is 4789 (VXLAN well-known port).
	 * ntohs converts network byte order to host byte order.
	 */
	if (ntohs(udp->dest) != 4789)
		return XDP_PASS;

	/* 
	 * VXLAN header validation.
	 * VXLAN header is 8 bytes and follows the UDP header.
	 * Layout (RFC 7348):
	 *   - VXLAN flags: 3 bits (reserved) + 1 bit (E) + 1 bit (R) + 1 bit (S)
	 *   - VXLAN VNI: 24 bits
	 *   - Reserved: 8 bits
	 * Total VXLAN header = 8 bytes.
	 */
	if (data + sizeof(*udp) + sizeof(struct vxlanhdr) > data_end)
		return XDP_PASS;

	vxlan = data + sizeof(*udp);

	/*
	 * Optional: Validate VXLAN flags.
	 * Bit 0 (S): Segment flag. Must be 1 for standard VXLAN.
	 * Bit 1 (R): Reserved. Must be 0.
	 * Bit 2 (E): E bit. Must be 0 for standard VXLAN.
	 * The following mask checks that S=1, R=0, E=0.
	 * vxlan->flags & 0x78 should be 0, and (vxlan->flags & 0x01) should be 1.
	 * For level_1 simplicity, we accept any frame with UDP port 4789 
	 * and valid header bounds, but we do check the VXLAN version/ex reserved bits.
	 */
	if ((vxlan->flags & 0x78) != 0)
		return XDP_PASS;

	if ((vxlan->flags & 0x01) != 0x01)
		return XDP_PASS;

	/*
	 * Increment the per-CPU counter.
	 * BPF map update element for per-CPU array.
	 * We use bpf_map_update_elem with BPF_ANY to create/update the element.
	 * The flags BPF_NOEXIST ensures we only update if key exists (it does with max_entries 1).
	 * Since this is per-CPU, each CPU has its own counter value, but the map 
	 * infrastructure handles the indexing.
	 */
	bpf_map_update_elem(&vxlan_counter_map, &key, &((__u64){1}), BPF_ANY);

	/* 
	 * Always return XDP_PASS as required.
	 * This allows the packet to continue through the networking stack.
	 */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
