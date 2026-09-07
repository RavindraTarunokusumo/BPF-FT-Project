#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

/* Per-source packet quota map.
 * Key:   __u32  - source IP address (saddr)
 * Value: __u64  - packet counter (atomic increment)
 */
struct {
	__uint	type,		BPF_MAP_TYPE_LRU_HASH;
	__uint	key_size,	sizeof(__u32);
	__uint	value_size, sizeof(__u64);
	__uint	max_entries,	256;
} client_quota_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_quota_inspector(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Verify Ethernet header bounds */
	struct eth_hdr *eth = data;
	if (data_end < (void *)(eth + 1))
		return XDP_PASS;

	/* Verify IPv4 header bounds */
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if (data_end < (void *)(ip + 1))
		return XDP_PASS;

	/* Only process IPv4 traffic; skip others */
	if (ip->version != 4)
		return XDP_PASS;

	/* Lookup and atomically increment per-source packet counter.
	 * BPF atomic fetch_add returns the *previous* value before increment.
	 */
	__u32 key = ip->saddr;
	__u64 *counter = bpf_map_lookup_elem(&client_quota_map, &key);
	if (!counter) {
		/* First packet from this source: initialize to 1 */
		__u64 init_val = 1;
		bpf_map_update_elem(&client_quota_map, &key, &init_val, BPF_ANY);
		counter = &init_val; /* point to the just-inserted value for the increment below */
		/* BPF_MAP_TYPE_LRU_HASH does not support atomic fetch_add on freshly inserted
		 * values via map_lookup_elem safely in all kernel versions, so we re-read
		 * the value after insertion to ensure correctness.
		 */
		counter = bpf_map_lookup_elem(&client_quota_map, &key);
		if (!counter)
			return XDP_PASS; /* should not happen */
	}

	/* Atomic increment: returns previous count */
	__u64 prev = bpf_atomic_fetch_add(counter, 1);

	/* Drop if per-source quota exceeded ( > 100 ) */
	if (prev >= 100)
		return XDP_DROP;

	/* Forward all other packets */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
