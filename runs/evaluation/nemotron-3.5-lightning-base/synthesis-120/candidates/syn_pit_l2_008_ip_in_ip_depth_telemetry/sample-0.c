#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* 
 * Per-CPU array map to track IP-in-IP tunnel depth.
 * max_entries 2: slot 0 = single encapsulation, slot 1 = double nested encapsulation
 */
struct {
	__uint	type,		BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries,	2;
	__uint(map_flags),	0;
} ipinip_depth_map SEC(".maps");

SEC("xdp")
int xdp_ipinip_depth_telemetry(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct eth_hdr *eth;
	struct iphdr *outer_ip;
	struct iphdr *inner_ip;
	__u16 outer_ihl;
	__u8 inner_proto;

	/* 
	 * Validate Ethernet frame boundaries.
	 * We need at least sizeof(struct eth_hdr) bytes.
	 */
	if (data + sizeof(struct eth_hdr) > data_end)
		return XDP_PASS;

	eth = data;

	/* 
	 * Validate outer IPv4 header.
	 * Check that the Ethernet frame contains enough data for the outer IP header.
	 * outer_ip->ihl is in 32-bit words, so multiply by 4 to get bytes.
	 */
	if (data + sizeof(struct eth_hdr) + (eth->h_proto == bpf_htons(ETH_P_IP) ? 0 : 0) > data_end)
		return XDP_PASS;

	/* 
	 * Quick check: is the EtherType IPv4? If not, we cannot have IP-in-IP.
	 * This check is implicit; we proceed to parse outer IP if structure allows.
	 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 
	 * Parse outer IPv4 header.
	 * The outer IP header starts immediately after the Ethernet header.
	 * We must ensure the outer IP header fits within the packet boundary.
	 */
	outer_ip = data + sizeof(struct eth_hdr);
	if ((void *)(outer_ip + 1) > data_end)
		return XDP_PASS;

	/* 
	 * Calculate outer IHL in bytes.
	 * iphdr->ihl is the number of 32-bit words.
	 */
	outer_ihl = outer_ip->ihl * 4;
	if (outer_ihl < sizeof(struct iphdr))
		return XDP_PASS;

	/* 
	 * Validate that the outer IP header + Ethernet header does not exceed data_end.
	 * We already checked outer_ip pointer, but we need to ensure the calculated IHL
	 * doesn't push us past the end.
	 */
	if ((void *)(outer_ip + outer_ihl) > data_end)
		return XDP_PASS;

	/* 
	 * Get the inner protocol field.
	 * The inner protocol is at the same offset as ip_proto in the outer iphdr,
	 * which is offset 9 from the start of the iphdr structure.
	 * Since outer_ip points to the start of the outer iphdr,
	 * inner_proto is at outer_ip + 9.
	 */
	inner_proto = outer_ip->protocol;

	/* 
	 * Determine inner IPv4 header location.
	 * Inner IP starts right after the outer IP header.
	 * Outer IHL might include options, so we use the calculated outer_ihl.
	 */
	inner_ip = (void *)outer_ip + outer_ihl;

	/* 
	 * Validate inner IPv4 header bounds.
	 * The inner IP header must fit within the remaining data.
	 */
	if ((void *)(inner_ip + 1) > data_end)
		return XDP_PASS;

	/* 
	 * Check inner IHL to ensure the inner header is valid.
	 * Similar to outer, inner->ihl is in 32-bit words.
	 */
	if (inner_ip->ihl < 5) /* minimum IHL is 5 (20 bytes) */
		return XDP_PASS;

	/* 
	 * Validate inner IP header bounds accounting for variable IHL.
	 * inner_ip + inner_ihl must not exceed data_end.
	 */
	if ((void *)(inner_ip + inner_ip->ihl * 4) > data_end)
		return XDP_PASS;

	/* 
	 * Check inner protocol:
	 * - If inner_proto != 4: single encapsulation (slot 0)
	 * - If inner_proto == 4: double nested encapsulation (slot 1)
	 */
	if (inner_proto != IPPROTO_IPIP) { /* IPPROTO_IPIP is 4 */
		/* Single encapsulation: increment slot 0 */
		bpf_map_update_elem(
			&ipinip_depth_map,
			&(int){0}, /* key */
			&(int){1}, /* value */
			BPF_ANY
		);
	} else {
		/* Double nested encapsulation: increment slot 1 */
		bpf_map_update_elem(
			&ipinip_depth_map,
			&(int){1}, /* key */
			&(int){1}, /* value */
			BPF_ANY
		);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
