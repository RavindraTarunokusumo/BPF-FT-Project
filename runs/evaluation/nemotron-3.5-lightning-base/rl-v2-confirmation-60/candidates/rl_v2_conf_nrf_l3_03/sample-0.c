#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* LPM trie map definition:
 * Key: prefixlen (u32) | data (u32, contains next-hop ifindex)
 * Value: __u32 next-hop ifindex (overridden by map value if needed)
 * Flags: BPF_F_NO_PREALLOC to disable preallocation of trie nodes
 */
struct redirect_key {
	__u32 prefixlen;
	__u32 data;
};

SEC("xdp")
int redirect_xdp_03(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Verify Ethernet header bounds */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Verify IPv4 header bounds */
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* Only process IPv4 packets */
	if (ip->version != 4)
		return XDP_PASS;

	/* Lookup destination address in the LPM trie map */
	/* Key: prefixlen=32 (exact match), data=ip->daddr */
	struct redirect_key key = {
		.prefixlen = 32,
		.data = ip->daddr,
	};

	__u32 *ifindex = bpf_map_lookup_elem(redirect_route_3, &key);
	if (ifindex) {
		/* Route hit: forward packet to the resolved interface */
		return bpf_redirect(*ifindex, 0);
	}

	/* Route miss: pass the packet to the network stack */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
