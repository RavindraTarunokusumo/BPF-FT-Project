#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* 
 * LPM trie map for redirect routes.
 * Key: prefixlen (u32) | data (u32, IP address)
 * Value: ifindex (u32)
 */
struct route_key {
	__u32 prefixlen;
	__u32 data;
};

SEC("xdp")
int xdp_redirect_route_01(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
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

	/* Lookup destination address in LPM trie map */
	/* prefixlen=32 means exact match on 32-bit daddr */
	ifindex = bpf_lpm_lookup(ctx, &redirect_route_1, 
				 (struct route_key){ .prefixlen = 32, .data = ip->daddr },
				 0);

	if (ifindex) {
		/* Route hit: redirect packet to the matched egress interface */
		return bpf_redirect(ifindex, 0);
	}

	/* Route miss: pass the packet to the network stack */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
