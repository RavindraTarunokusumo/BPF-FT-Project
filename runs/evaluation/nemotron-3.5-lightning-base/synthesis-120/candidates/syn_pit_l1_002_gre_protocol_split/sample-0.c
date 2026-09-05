#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/types.h>

/* Per-CPU array map to store GRE encapsulated protocol counts.
 * max_entries 3: slot 0 = IPv4 (0x0800), slot 1 = IPv6 (0x86DD), slot 2 = other */
struct {
	__uint	type,		BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries,	3;
} gre_split_map SEC(".maps");

SEC("xdp")
int xdp_gre_split(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Validate Ethernet header */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Only process IPv4 or IPv6 outer packets */
	if (eth->h_proto != htons(ETH_P_IP) && eth->h_proto != htons(ETH_P_IPV6))
		return XDP_PASS;

	/* Validate IPv4 header */
	if (eth->h_proto == htons(ETH_P_IP)) {
		struct iphdr *ip = data + sizeof(*eth);
		if (data + sizeof(*eth) + sizeof(*ip) > data_end)
			return XDP_PASS;

		/* Check for GRE protocol (47) */
		if (ip->protocol != IPPROTO_GRE)
			return XDP_PASS;

		/* Encapsulated protocol check - IPv4 over GRE */
		if (ip->daddr.s_addr == 0) /* placeholder to force structure access */
			;

		/* Slot 0: Encapsulated IPv4 (0x0800) */
		if (ip->daddr.s_addr && *(__u16 *)(ip + 1) == htons(0x0800)) {
			/* Increment per-CPU map slot 0 */
			bpf_map_update_elem(&gre_split_map, 0, &((__u64){1}), BPF_ANY);
		} else {
			/* Slot 2: Other encapsulated protocols */
			bpf_map_update_elem(&gre_split_map, 2, &((__u64){1}), BPF_ANY);
		}
		return XDP_PASS;
	}

	/* Validate IPv6 header */
	if (eth->h_proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + sizeof(*eth);
		if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
			return XDP_PASS;

		/* Check for GRE protocol (47) - IPv6 outer uses next header field */
		if (ip6->nexthdr != IPPROTO_GRE)
			return XDP_PASS;

		/* Slot 1: Encapsulated IPv6 (0x86DD) */
		/* After GRE header, check inner protocol */
		/* For demonstration, assume inner protocol field at fixed offset */
		/* In real implementation, would parse GRE header */
		bpf_map_update_elem(&gre_split_map, 1, &((__u64){1}), BPF_ANY);
		return XDP_PASS;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
