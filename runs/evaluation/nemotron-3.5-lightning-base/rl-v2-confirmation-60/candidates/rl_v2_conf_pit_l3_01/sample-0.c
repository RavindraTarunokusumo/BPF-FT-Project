#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Define the per-flow timing structure */
struct flow_timing {
	__u64 first_seen;
	__u64 last_seen;
};

/* LRU Hash map keyed by __u32 (source IP), value is struct flow_timing */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct flow_timing));
	__uint(max_entries, 4096);
} flow_time_01 SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_flow_timing(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	__u32 key;
	struct flow_timing *ft;

	/* Verify Ethernet header bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* Verify IPv4 header bounds */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = (struct iphdr *)(eth + 1);

	/* Only process IPv4 packets (version == 4) */
	if (ip->version != 4)
		return XDP_PASS;

	/* Key is the source IP address */
	key = ip->saddr;

	/* Look up existing flow timing */
	ft = bpf_map_lookup_elem(flow_time_01, &key, NULL);
	if (ft) {
		/* Update last_seen if this packet is newer */
		__u64 now = bpf_ktime_get_ns();
		if (now > ft->last_seen)
			ft->last_seen = now;
	} else {
		/* First-seen: allocate and record both timestamps */
		struct flow_timing new_ft = {
			.first_seen = bpf_ktime_get_ns(),
			.last_seen  = bpf_ktime_get_ns(),
		};
		bpf_map_update_elem(flow_time_01, &key, &new_ft, BPF_ANY);
	}

	/* Unconditionally pass the packet */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
