#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

/* BPF map definition: LRU hash map to store quarantined source IP addresses.
 * Key: __u32 (source IP address)
 * Value: __u32 (can be used for additional info, e.g., timestamp or quarantine level;
 *         for this task we only need the key, but a value is required by the map type)
 * Max entries: 1024 */
struct {
	__uint	type, BPF_MAP_TYPE_LRU_HASH;
	__uint	max_entries, 1024;
	__type(key, __u32);
	__type(value, __u32);
} quarantine_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_quarantine_filter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Verify Ethernet header bounds */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Verify IPv4 header bounds */
	/* Check EtherType == 0x0800 (IPv4) */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* Lookup source IP address in quarantine_map */
	__u32 key = ip->saddr;
	__u32 value = 0; /* value is not used for the lookup, but required by map definition */

	if (bpf_map_lookup_elem(&quarantine_map, &key, &value) == 0) {
		/* Key found in map -> packet is from a quarantined source */
		return XDP_DROP;
	}

	/* Key not found -> allow packet */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
