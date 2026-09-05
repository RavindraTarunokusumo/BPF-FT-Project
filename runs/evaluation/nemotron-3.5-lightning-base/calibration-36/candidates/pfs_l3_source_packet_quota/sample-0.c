/* XDP program: Per-source IPv4 packet quota enforcement
 *
 * Enforces a per-source IPv4 packet quota of 5 packets per source IP address.
 * - First 5 packets from a source are passed (XDP_PASS).
 * - Packets beyond the 5th from the same source are dropped (XDP_DROP).
 * - Non-IPv4 traffic is passed without quota enforcement.
 *
 * License: GPL
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Define the BPF hash map for source IP tracking.
 * Key: __u32 (IPv4 source address)
 * Val: __u64 (packet counter)
 * Max entries: 10240
 */
struct {
	__uint	type, BPF_MAP_TYPE_HASH;
	__uint	key_size, sizeof(__u32);
	__uint	value_size, sizeof(__u64);
	__uint	max_entries, 10240;
} source_quota_map SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_source_quota(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* 1. Safely parse Ethernet header */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* 2. Check for IPv4 protocol (ETH_P_IP = 0x0800) */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 3. Safely parse IPv4 header */
	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 4. Extract source IPv4 address (__be32 -> __u32) */
	__u32 saddr = ip->saddr;

	/* 5. Lookup existing quota count from the hash map */
	__u64 *val;
	val = bpf_map_lookup_elem(&source_quota_map, &saddr);
	if (val) {
		/* Existing entry: increment count */
		(*val) += 1;

		/* If count exceeds 5, drop the packet */
		if (*val > 5)
			return XDP_DROP;
		else
			return XDP_PASS;
	}

	/* 6. First packet from this source: insert with count=1 */
	__u64 init_count = 1;
	int ret;

	/* BPF_ANY: insert if key does not exist (overwrite if exists, but we checked) */
	ret = bpf_map_update_elem(&source_quota_map, &saddr, &init_count, BPF_ANY);
	if (ret) {
		/* Map update failed; pass the packet */
		return XDP_PASS;
	}

	/* First packet: pass and count is 1 */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
