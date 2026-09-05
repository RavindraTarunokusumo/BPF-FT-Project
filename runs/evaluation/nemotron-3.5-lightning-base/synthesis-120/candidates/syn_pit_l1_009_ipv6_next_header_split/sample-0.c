#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>

/* Per-CPU array map to count IPv6 next headers.
 * max_entries 4: slot 0=TCP(6), slot 1=UDP(17), slot 2=ICMPv6(58), slot 3=other
 */
struct {
	__uint	type,		BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries,	4;
	__uint(map_flags),	0;
	__type(values, __u64);
} ipv6_proto_map SEC(".maps");

SEC("xdp")
int xdp_ipv6_proto_count(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Validate Ethernet frame boundary */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Only process IPv6 packets (EtherType 0x86DD) */
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return XDP_PASS;

	/* Validate IPv6 header boundary (40 bytes) */
	struct ipv6hdr *ip6 = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
		return XDP_PASS;

	/* Inspect the Next Header field (nexthdr) at offset 6 from ipv6hdr start.
	 * ipv6hdr->nexthdr is a __u8.
	 */
	__u8 nexthdr = ip6->nexthdr;

	/* Map slot selection:
	 * slot 0 -> TCP (6)
	 * slot 1 -> UDP (17)
	 * slot 2 -> ICMPv6 (58)
	 * slot 3 -> all other next headers
	 */
	__u64 *slot;
	int idx;

	if (nexthdr == IPPROTO_TCP)
		idx = 0;
	else if (nexthdr == IPPROTO_UDP)
		idx = 1;
	else if (nexthdr == IPPROTO_ICMPV6)
		idx = 2;
	else
		idx = 3;

	/* Increment the per-CPU counter for the selected slot */
	slot = bpf_map_lookup_elem(&ipv6_proto_map, &idx);
	if (slot) {
		(*slot)++;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
