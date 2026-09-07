#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Define the timing structure for flow tracking */
struct flow_timing {
	__u64 first_seen;
	__u64 last_seen;
};

/* LRU Hash map keyed by __u32 (IP address), value is struct flow_timing */
struct {
	__uint	type, BPF_MAP_TYPE_LRU_HASH;
	__uint	key_size, sizeof(__u32);
	__uint	value_size, sizeof(struct flow_timing);
	__uint(max_entries, 4096);
} flow_time_04 SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	__u32 ip_key;
	int ret;

	/* Verify Ethernet frame bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	/* Verify IPv4 protocol and header bounds */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = (struct iphdr *)(eth + 1);

	/* Only process IPv4 traffic (version check) */
	if (ip->version != 4)
		return XDP_PASS;

	/* Use destination address as flow key (__u32) */
	ip_key = (__u32)ip->daddr;

	/* Query existing flow timing entry */
	struct flow_timing *timing = bpf_map_lookup_elem(&flow_time_04, &ip_key);
	if (timing) {
		/* Update last_seen if already present */
		timing->last_seen = bpf_ktime_get_ns();
	} else {
		/* Allocate new entry and set first_seen and last_seen */
		struct flow_timing new_timing = {
			.first_seen = bpf_ktime_get_ns(),
			.last_seen  = bpf_ktime_get_ns(),
		};
		bpf_map_update_elem(&flow_time_04, &ip_key, &new_timing, BPF_ANY);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
