/* XDP program: ipv4_split
 * Category: packet_inspection_telemetry
 * Difficulty: level_1
 *
 * Increments per-CPU counters for IPv4 and non-IPv4 frames.
 * Returns XDP_PASS for all frames.
 *
 * Map: ip_split_counter (BPF_MAP_TYPE_PERCPU_ARRAY)
 *   key 0 -> IPv4 count (__u64)
 *   key 1 -> non-IPv4 count (__u64)
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

/* Per-CPU array map definition.
 * max_entries = 2 (keys 0 and 1).
 * Key type: __u32 (implicit from BPF_MAP_TYPE_PERCPU_ARRAY).
 * Value type: __u64.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(val, __u64);
} ip_split_counter SEC(".maps");

SEC("xdp")
int xdp_ipv4_split(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Check Ethernet header bounds. */
	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	struct ethhdr *eth = data;

	/* Determine slot: 0 for IPv4, 1 for everything else. */
	int slot;
	if (eth->h_proto == bpf_htons(ETH_P_IP))
		slot = 0;
	else
		slot = 1;

	/* Lookup and increment the per-CPU counter. */
	__u64 *counter = bpf_map_lookup_elem(&ip_split_counter, &slot);
	if (counter) {
		(*counter)++;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
