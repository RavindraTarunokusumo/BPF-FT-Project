#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* 
 * LPM trie map definition.
 * BPF_F_NO_PREALLOC ensures the map is created without pre-allocating
 * the internal radix tree nodes, allowing dynamic insertion.
 */
struct bpf_map_def __attribute__((section("maps"))) redirect_route_4 = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = 8,   /* sizeof(struct route_key) */
	.value_size = 4, /* sizeof(__u32 ifindex) */
	.max_entries = 1024,
	.flags = BPF_F_NO_PREALLOC,
};

/*
 * LPM key structure for the trie lookup.
 * prefixlen: The prefix length (32 for host routes / IPv4).
 * data:      The actual prefix value (IP address).
 */
struct route_key {
	__u32 prefixlen;
	__u32 data;
};

/* XDP entry point */
SEC("xdp")
int xdp_redirect_route_04(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct route_key key;
	__u32 ifindex = 0;

	/* Verify Ethernet header bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* Verify IPv4 header bounds */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = (struct iphdr *)(eth + 1);

	/* Only process IPv4 packets */
	if (ip->version != 4)
		return XDP_PASS;

	/* Construct LPM trie key:
	 * prefixlen = 32 (host route / specific IP match)
	 * data      = destination IP address */
	key.prefixlen = 32;
	key.data = ip->daddr;

	/* Lookup the destination IP in the LPM trie map.
	 * The map 'redirect_route_4' returns the associated ifindex
	 * if a matching route exists, otherwise returns 0 (not found). */
	if (bpf_lpm_trie_lookup(&redirect_route_4, &key, sizeof(key), &ifindex, 0) == 0) {
		/* Route hit: forward packet to the target interface index */
		if (ifindex)
			return bpf_redirect(ifindex, 0);
	}

	/* Route miss (or ifindex == 0): pass the packet to the network stack */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
