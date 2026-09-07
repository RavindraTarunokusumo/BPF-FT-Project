/* XDP program: ICMPv6 Neighbor Discovery Telemetry
 * Inspects IPv6 ICMPv6 ND traffic and counts types in a per-CPU array map.
 * Types tracked: Router Solicitation (133), Router Advertisement (134),
 *                Neighbor Solicitation (135), Neighbor Advertisement (136).
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

/* Per-CPU array map with 4 slots for ICMPv6 ND message types */
struct {
	__uint	type, SEC("maps");
	__uint(max_entries, 4);
	__type(array, __u64);
} nd_telemetry_map SEC(".maps");

SEC("xdp")
int xdp_nd_telemetry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmp6;

	/* 1. Validate Ethernet frame minimum size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Validate IPv6 protocol (Next Header 58 is ICMPv6) */
	/* eth->h_proto is network byte order (big-endian) */
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return XDP_PASS;

	ip6 = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
		return XDP_PASS;

	/* Verify Next Header field is ICMPv6 (58) */
	/* ip6->nexthdr is in host byte order after ntohs/htonl handling,
	 * but typically stored as raw byte; use direct comparison. */
	if (ip6->nexthdr != IPPROTO_ICMPV6)
		return XDP_PASS;

	/* 3. Validate ICMPv6 header */
	if (data + sizeof(*eth) + sizeof(*ip6) + sizeof(*icmp6) > data_end)
		return XDP_PASS;

	icmp6 = data + sizeof(*eth) + sizeof(*ip6);

	/* 4. Check ICMPv6 type in range 133..136 and increment corresponding slot */
	if (icmp6->icmp6_type >= 133 && icmp6->icmp6_type <= 136) {
		int slot = icmp6->icmp6_type - 133;
		__u64 *counter;

		counter = bpf_map_lookup_elem(nd_telemetry_map, &slot);
		if (!counter)
			return XDP_PASS;

		/* Increment the per-CPU counter atomically */
		*counter = bpf_atomic_add(1, counter);
	}

	/* 5. Always return XDP_PASS */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
