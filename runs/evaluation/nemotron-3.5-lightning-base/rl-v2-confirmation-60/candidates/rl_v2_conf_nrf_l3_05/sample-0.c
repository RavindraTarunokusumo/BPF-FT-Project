#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* 
 * LPM trie map for route redirection.
 * Key: prefixlen (8 bits) | data (24 bits IPv4 address)
 * Value: __u32 ifindex of the target interface
 */
struct route_key {
	__u32 prefixlen;
	__u32 data;
};

SEC("xdp")
int redirect_xdp_05(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct eth_hdr *eth;
	struct iphdr *ip;

	/* Verify Ethernet header bounds */
	eth = data;
	if (data_end - data < sizeof(*eth))
		return XDP_PASS;

	/* Verify IPv4 header bounds */
	if (data_end - data < sizeof(*eth) + sizeof(*ip))
		return XDP_PASS;

	ip = (struct iphdr *)(eth + 1);

	/* Only process IPv4 packets */
	if (ip->version != 4)
		return XDP_PASS;

	/* Lookup destination address in the LPM trie map */
	/* prefixlen=32 means exact match on 32-bit daddr */
	struct route_key key = {
		.prefixlen = 32,
		.data = ip->daddr,
	};

	__u32 *ifindex;
	int ret;

	ret = bpf_lpm_trie_lookup(&redirect_route_5, &key, sizeof(key), &ifindex, 0);
	if (ret) {
		/* Route miss: pass the packet to the normal stack */
		return XDP_PASS;
	}

	/* Route hit: redirect to the resolved interface */
	return bpf_redirect(*ifindex, 0);
}

char LICENSE[] = "GPL";
