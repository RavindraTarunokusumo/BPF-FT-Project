#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* LRU Hash map: key is __u32 (destination IP), value is __u64 (accumulated bytes) */
struct {
	__uint	type, BPF_MAP_TYPE_LRU_HASH;
	__uint	max_entries, 256;
	__type(key, __u32);
	__type(value, __u64);
} dst_bytes_01 SEC(".maps");

SEC("xdp")
int xdp_dst_bytes_01(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;

	/* Verify Ethernet frame minimum size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* Verify IPv4 protocol and header bounds */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);

	/* Only process IPv4 */
	if (ip->version != 4)
		return XDP_PASS;

	/* Atomically add byte count to map entry */
	__u32 key = ip->daddr;
	__u64 val = bpf_ntohs(ip->tot_len);
	__u64 *prev;

	prev = bpf_map_lookup_elem(&dst_bytes_01, &key);
	if (prev) {
		/* Entry exists: atomic add */
		bpf_atomic_add64(val, prev);
	} else {
		/* Entry does not exist: initialize with packet length */
		__u64 init_val = val;
		bpf_map_update_elem(&dst_bytes_01, &key, &init_val, BPF_ANY);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
