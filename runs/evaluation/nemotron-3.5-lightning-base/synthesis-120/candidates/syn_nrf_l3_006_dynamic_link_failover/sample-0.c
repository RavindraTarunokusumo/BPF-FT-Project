#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/* 
 * Array map to store link status.
 * Key: 0 (primary link status)
 * Value: __u32 status (1 = UP, 0 = DOWN)
 * max_entries: 1
 */
struct {
	__uint	type, BPF_MAP_TYPE_ARRAY;
	__uint	max_entries, 1;
	__type(key, __u32);
	__type(value, __u32);
} link_status_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_dynamic_link_failover(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	__u32 status;
	__u32 ifindex;

	/* 
	 * Validate Ethernet frame bounds.
	 * We need at least sizeof(struct eth_hdr) bytes.
	 */
	if (data + sizeof(struct eth_hdr) > data_end)
		return XDP_PASS;

	eth = data;

	/* 
	 * Check Ethernet type. Only process IPv4 (0x0800).
	 * Non-IPv4 traffic is passed through unchanged.
	 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 
	 * Validate IPv4 header bounds.
	 * The Ethernet header is already validated.
	 * We need at least sizeof(struct iphdr) bytes starting after Ethernet header.
	 */
	if (data + sizeof(struct eth_hdr) + sizeof(struct iphdr) > data_end)
		return XDP_PASS;

	ip = (struct iphdr *)(eth + 1);

	/* 
	 * Check IPv4 version. 
	 * struct iphdr->version is in the upper 4 bits of the first byte (IHL version).
	 * We mask with 0xF0 and shift right 4 to get the version field.
	 */
	if ((ip->version & 0xF0) != 4)
		return XDP_PASS;

	/* 
	 * Read link status from BPF map.
	 * Key 0 corresponds to the primary link status.
	 */
	status = bpf_map_lookup_elem(&link_status_map, &(__u32){0}, &status);
	if (!status) {
		/* 
		 * If the map does not contain key 0, assume primary link is UP 
		 * (fallback default behavior) or pass traffic. 
		 * Here we choose to pass traffic to avoid dropping packets 
		 * due to missing configuration.
		 */
		return XDP_PASS;
	}

	/* 
	 * Dynamic link failover logic:
	 * - If status == 1 (primary UP), redirect to primary interface ifindex 80
	 * - If status == 0 (primary DOWN), fail over to backup interface ifindex 81
	 */
	if (status == 1) {
		/* Primary link is UP -> redirect to primary interface */
		ifindex = 80;
	} else {
		/* Primary link is DOWN -> fail over to backup interface */
		ifindex = 81;
	}

	/* 
	 * Redirect the packet to the specified interface.
	 * bpf_redirect_ifindex takes the interface index and flags.
	 * XDP_REDIRECT is the standard flag for XDP programs.
	 */
	return bpf_redirect_ifindex(ifindex, 0);
}

char _license[] SEC("license") = "GPL";
