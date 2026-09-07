#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <uapi/linux/pkt_cls.h>

/* 
 * BPF map to track burst timestamps per source IP.
 * Key: source IP address (__u32)
 * Value: last arrival timestamp in nanoseconds (__u64)
 */
struct {
	__uint	type, BPF_MAP_TYPE_HASH;
	__uint	key_size, sizeof(__u32);
	__uint	value_size, sizeof(__u64);
	__uint	max_entries, 256;
} burst_timestamp_map SEC(".maps");

SEC("xdp")
int xdp_burst_throttle(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Verify Ethernet header bounds */
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Verify IPv4 header bounds */
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* Only process IPv4 traffic */
	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	/* Get current timestamp */
	__u64 now = bpf_ktime_get_ns();

	/* Lookup last timestamp for source IP */
	__u32 key = ip->saddr;
	__u64 *last_time = bpf_map_lookup_elem(&burst_timestamp_map, &key);

	__u64 threshold = 1000000ULL; /* 1 ms */

	if (last_time && (*last_time > now - threshold)) {
		/* Drop back-to-back arrival within threshold */
		return XDP_DROP;
	}

	/* Update timestamp in map */
	bpf_map_update_elem(&burst_timestamp_map, &key, &now, BPF_ANY);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
