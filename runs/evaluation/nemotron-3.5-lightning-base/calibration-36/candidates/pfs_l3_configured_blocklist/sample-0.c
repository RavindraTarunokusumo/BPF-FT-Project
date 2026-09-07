/* XDP program: LPM-configured blocklist filter
 *
 * Consults an LPM-trie blocklist map. If the source IPv4 address matches
 * a blocked prefix, the per-rule match counter is incremented and the
 * packet is dropped. Non-IPv4 frames and unmatched packets are passed.
 *
 * Maps (defined externally / via bpftool):
 *   blocklist_lpm_map  - BPF_MAP_TYPE_LPM_TRIE, key: { __u32 prefixlen; __u32 ip; },
 *                        val: __u32 rule_id, max_entries 1024, flags BPF_F_NO_PREALLOC
 *   rule_counter_map   - BPF_MAP_TYPE_ARRAY,   key: __u32 rule_id,
 *                        val: __u64 match_count, max_entries 64
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* LPM trie key layout matching the map definition */
struct blocklist_key {
	__u32 prefixlen;
	__u32 ip;
};

/* Map definitions – names must match the loader */
struct {
	__uint	type,		BPF_MAP_TYPE_LPM_TRIE;
	__uint	max_entries,	1024;
	__uint	flags,		BPF_F_NO_PREALLOC;
} blocklist_lpm_map SEC(".maps");

struct {
	__uint	type,		BPF_MAP_TYPE_ARRAY;
	__uint	max_entries,	64;
} rule_counter_map SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_blocklist(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* 1. Verify Ethernet frame bounds */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* 2. Accept only IPv4 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 3. Verify IPv4 frame bounds */
	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 4. Build LPM trie key: prefixlen = 32 (host byte order) */
	struct blocklist_key key = {
		.prefixlen = 32,
		.ip        = ip->saddr, /* source IP (network byte order) */
	};

	/* 5. Lookup in blocklist_lpm_map */
	__u32 rule_id = 0;
	int ret = bpf_lpm_lookup(ctx, &blocklist_lpm_map, &key, sizeof(key), &rule_id);
	if (ret < 0)
		return XDP_PASS; /* no match or map error */

	/* 6. Increment per-rule counter */
	__u64 *counter = bpf_map_lookup_elem(rule_counter_map, &rule_id);
	if (!counter)
		return XDP_DROP; /* rule exists but counter missing – drop safely */

	__sync_add_and_counter(counter, 1); /* atomic increment */
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
