#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/*
 * Struct to store first_seen and last_seen timestamps per flow.
 * Key is __u32 (IP source address).
 */
struct flow_timing {
	__u64 first_seen;
	__u64 last_seen;
};

/*
 * LRU hash map keyed by __u32 (IP src addr), value is struct flow_timing.
 * Map name: flow_time_05
 */
struct {
	__uint	type, BPF_MAP_TYPE_LRU_HASH;
	__uint	key_size, sizeof(__u32);
	__uint	value_size, sizeof(struct flow_timing);
	__uint(max_entries, 4096);
} flow_time_05 SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_prog_05(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	__u32 key;
	int ret;

	/* Verify Ethernet frame bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	/* Verify IPv4 payload bounds */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = (struct iphdr *)(eth + 1);

	/* Only process IPv4 (ETH_P_IP = 0x0800) */
	if (ip->version != 4)
		return XDP_PASS;

	/* Key is the source IP address */
	key = ip->saddr;

	/* Query existing entry */
	struct flow_timing *val = bpf_map_lookup_elem(&flow_time_05, &key);
	if (val) {
		/* Update last_seen if already present */
		val->last_seen = bpf_ktime_get_ns();
	} else {
		/* First time seeing this flow: set both first_seen and last_seen */
		struct flow_timing new_val = {
			.first_seen = bpf_ktime_get_ns(),
			.last_seen  = bpf_ktime_get_ns(),
		};
		bpf_map_update_elem(&flow_time_05, &key, &new_val, BPF_ANY);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
