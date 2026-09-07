#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* 
 * BPF_MAP_TYPE_HASH map to track SYN packet rates per /24 subnet.
 * Key: __u32 (subnet address, lower 24 bits of source IP)
 * Value: __u32 (SYN count for that subnet)
 */
struct {
	__uint	type,		BPF_MAP_TYPE_HASH;
	__uint	key_size,		4;
	__uint	value_size,	4;
	__uint(max_entries),	256;
} syn_subnet_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_syn_flood_defender(struct xdp_md *ctx)
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

	/* Only process IPv4 traffic */
	if (ip->version != 4)
		return XDP_PASS;

	/* Verify TCP header bounds */
	struct tcphdr *tcp = (void *)ip + sizeof(*ip);
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
		return XDP_PASS;

	/* Check for TCP SYN flag */
	if (!(tcp->syn))
		return XDP_PASS;

	/* Extract /24 subnet from source IP (lower 24 bits) */
	__u32 subnet = ip->saddr & 0x00FFFFFF;

	/* Lookup current SYN count for this subnet */
	__u32 *count = bpf_map_lookup_elem(syn_subnet_map, &subnet);
	if (count) {
		/* Increment SYN count */
		(*count)++;

		/* Drop if count exceeds 200 */
		if (*count > 200)
			return XDP_DROP;
	} else {
		/* First SYN from this subnet, initialize count to 1 */
		__u32 init_val = 1;
		bpf_map_update_elem(syn_subnet_map, &subnet, &init_val, BPF_ANY);
	}

	/* Allow packet through */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
