/* XDP program: nrf_l2_protocol_redirect
 *
 * Redirects IPv4 TCP and UDP packets to separately configured egress interfaces
 * using an array map 'proto_redirect_map'.
 *
 * Map layout:
 *   key 0 -> val: ifindex for TCP (max_entries=2)
 *   key 1 -> val: ifindex for UDP (max_entries=2)
 *
 * Behaviour:
 *   - IPv4 TCP  : lookup key 0; if val > 0 -> bpf_redirect(val, 0) else XDP_PASS
 *   - IPv4 UDP  : lookup key 1; if val > 0 -> bpf_redirect(val, 0) else XDP_PASS
 *   - Other     : XDP_PASS
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Map definition:
 *   type: BPF_MAP_TYPE_ARRAY
 *   key: __u32  (0 = TCP, 1 = UDP)
 *   val:  __u32 (ifindex, 0 means pass)
 *   max_entries: 2
 */
struct {
	__uint	type, BPF_MAP_TYPE_ARRAY;
	__uint	key_size, sizeof(__u32);
	__uint	value_size, sizeof(__u32);
	__uint	max_entries, 2;
} proto_redirect_map SEC(".maps");

SEC("xdp")
int nrf_l2_protocol_redirect(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Basic Ethernet frame bounds check */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* IPv4 protocol check */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* Only process IPv4; ip->version is already guaranteed by ETH_P_IP check,
	 * but we keep a sanity check for the IHL. */
	if (ip->version != 4)
		return XDP_PASS;

	/* --- TCP handling --- */
	if (ip->protocol == IPPROTO_TCP) {
		__u32 key = 0;
		__u32 *ifindex;

		ifindex = bpf_map_lookup_elem(&proto_redirect_map, &key);
		if (ifindex && *ifindex > 0) {
			return bpf_redirect(*ifindex, 0);
		}
		return XDP_PASS;
	}

	/* --- UDP handling --- */
	if (ip->protocol == IPPROTO_UDP) {
		__u32 key = 1;
		__u32 *ifindex;

		ifindex = bpf_map_lookup_elem(&proto_redirect_map, &key);
		if (ifindex && *ifindex > 0) {
			return bpf_redirect(*ifindex, 0);
		}
		return XDP_PASS;
	}

	/* --- All other protocols (ICMP, GRE, etc.) --- */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
