/* XDP Policy Router
 *
 * This program implements a simple LPM-based policy routing mechanism.
 * It looks up the source IP of incoming IPv4 packets in an LPM trie map.
 * If a matching rule exists and the protocol and destination IP criteria
 * are satisfied, the packet is redirected to a specific egress interface
 * via a DEVMAP. Otherwise, the packet is passed to the network stack.
 *
 * Maps:
 *   - policy_rules: LPM trie for source IP matching.
 *   - policy_devmap: DEVMAP for egress interface redirection.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/ctx.h>
#include <bpf/helpers.h>
#include <bpf/libbpf.h>

/* LPM Trie Key: prefixlen and source IP */
struct policy_key {
	__u32	prefixlen;
	__u32	src_ip;
};

/* LPM Trie Value: destination prefix, protocol filter, and egress index */
struct policy_val {
	__u32	dst_prefix;
	__u8	proto;
	__u32	egress_idx;
};

/* DEVMAP for egress interfaces */
struct bpf_map_def __attribute__((section("maps"))) policy_devmap = {
	.type		= BPF_MAP_TYPE_DEVMAP,
	.key_size	= sizeof(__u32),
	.val_size	= sizeof(__u32),
	.max_entries	= 4,
};

/* LPM Trie Map for routing rules */
struct bpf_map_def __attribute__((section("maps"))) policy_rules = {
	.type		= BPF_MAP_TYPE_LPM_TRIE,
	.key_size	= sizeof(struct policy_key),
	.val_size	= sizeof(struct policy_val),
	.max_entries	= 256,
	.flags		= BPF_F_NO_PREALLOC,
};

/* XDP entry point */
SEC("xdp")
int xdp_policy_router(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* 1. Check Ethernet frame bounds */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* 2. Drop non-IPv4 frames (except ARP etc.) - we only handle IPv4 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 3. Check IPv4 header bounds */
	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 4. Prepare LPM trie lookup key */
	/* We use prefixlen = 32 to match exact source IP */
	struct policy_key key = {
		.prefixlen	= 32,
		.src_ip		= ip->saddr, /* Already in network byte order */
	};

	/* 5. Lookup rule in policy_rules LPM trie */
	struct policy_val val = {};
	int ret = bpf_lpm_trie_lookup(&policy_rules, &key, sizeof(key), &val, sizeof(val));
	if (ret < 0) {
		/* Lookup failed, pass packet */
		return XDP_PASS;
	}

	/* 6. Validate protocol filter */
	/* Rule proto == 0 means match all protocols, otherwise match specific proto */
	if (val.proto != 0 && val.proto != ip->protocol)
		return XDP_PASS;

	/* 7. Validate destination IP prefix match */
	/* Check if the top 'dst_prefix' bits of the destination IP match rule->dst_prefix */
	__u32 dst_mask = val.dst_prefix; /* Assume dst_prefix is the number of bits to match */
	/* Construct a mask with 'dst_prefix' high bits set */
	__u32 prefix_mask = (dst_prefix == 32) ? ~0U :
			    (dst_prefix == 0) ? 0U :
			    (~(0xFFFFFFFF << (32 - dst_prefix)));

	/* Apply mask to packet destination IP */
	__u32 pkt_dst = bpf_ntohl(ip->daddr) & prefix_mask;
	__u32 rule_dst = bpf_ntohl(val.dst_prefix) & prefix_mask;

	if (pkt_dst != rule_dst)
		return XDP_PASS;

	/* 8. Redirect packet via DEVMAP to the egress interface */
	/* rule->egress_idx identifies the interface in policy_devmap */
	return bpf_redirect_map(&policy_devmap, val.egress_idx, 0);
}

char _license[] SEC("license") = "GPL";
