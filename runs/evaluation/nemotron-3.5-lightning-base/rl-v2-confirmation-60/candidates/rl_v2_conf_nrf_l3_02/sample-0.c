#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* 
 * LPM trie map for route redirection.
 * Key: prefixlen (u32) | data (u32 - IP address)
 * Value: ifindex (u32)
 */
#define MAP_NAME "redirect_route_02"
#define MAP_TYPE 5  /* BPF_MAP_TYPE_LPM_TRIE */
#define MAP_FLAGS BPF_F_NO_PREALLOC

struct route_key {
	__u32 prefixlen;
	__u32 data;
};

/* 
 * XDP program: port redirection via LPM trie lookup.
 * On route match: bpf_redirect to target interface index.
 * On route miss: XDP_PASS.
 */
SEC("xdp")
int xdp_redirect_route_02(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	__u32 ifindex = 0;
	int action = XDP_PASS;

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

	/* Lookup destination IP in LPM trie map with /32 prefix */
	if (bpf_lpm_lookup(ctx, &redirect_route_02, &ip->daddr, 32, &ifindex))
		return XDP_PASS;

	/* Route hit: redirect to target interface index */
	bpf_redirect(ifindex, 0);

	return action;
}

char LICENSE[] SEC("license") = "GPL";
