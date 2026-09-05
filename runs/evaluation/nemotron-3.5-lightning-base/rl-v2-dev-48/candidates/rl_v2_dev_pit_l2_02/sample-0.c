#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Map to accumulate per-destination-IP byte counts.
 * Key:   __u32  (destination IP address)
 * Value: __u64  (accumulated byte count)
 */
struct {
	__uint	type,		BPF_MAP_TYPE_LRU_HASH;
	__uint	key_size,	sizeof(__u32);
	__uint	value_size, sizeof(__u64);
	__uint	max_entries,	256;
} dst_bytes_02 SEC(".maps");

SEC("xdp")
int xdp_dst_bytes_02(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Verify Ethernet header bounds */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Verify IPv4 header bounds */
	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* Ensure the protocol field indicates IPv4 (0x0800) */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* Accumulate bpf_ntohs(ip->tot_len) for destination IP ip->daddr */
	__u32 daddr = ip->daddr;
	__u64 byte_count = bpf_ntohs(ip->tot_len);

	/* Lookup or insert the accumulated value atomically.
	 * bpf_map_update_elem with BPF_ANY will:
	 *   - Insert a new __u64 value initialized to 0 if key is absent.
	 *   - Update the existing __u64 value if key is present.
	 * We add byte_count to the fetched/current value.
	 */
	__u64 *val = bpf_map_lookup_elem(&dst_bytes_02, &daddr);
	if (val) {
		*val += byte_count;
	} else {
		__u64 init = byte_count;
		bpf_map_update_elem(&dst_bytes_02, &daddr, &init, BPF_ANY);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
