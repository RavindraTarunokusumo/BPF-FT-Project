#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

/* Map to track cumulative octets per destination IP.
 * Key:   __u32  (destination IP address)
 * Value: __u64  (cumulative byte count)
 */
struct {
	__uint	type, BPF_MAP_TYPE_LRU_HASH;
	__uint	max_entries, 256;
} dst_bytes_04 SEC(".maps");

SEC("xdp")
int xdp_dst_bytes_04(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct eth_hdr *eth;
	struct iphdr *ip;

	/* Verify Ethernet header bounds */
	eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Verify IPv4 header bounds */
	ip = (struct iphdr *)(eth + 1);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* Only process IPv4 packets (ip->version == 4) */
	if (ip->version != 4)
		return XDP_PASS;

	/* Atomically add packet total length to the per-destination-IP counter.
	 * bpf_ntohs converts the 16-bit tot_len from network to host byte order.
	 * bpf_lru_hash_update returns 0 on success, non-zero on failure.
	 * We ignore the return value as the map has sufficient entries.
	 */
	__u64 val = bpf_ntohs(ip->tot_len);
	__u32 key = ip->daddr;

	bpf_lru_hash_update(&dst_bytes_04, &key, &val, BPF_ANY);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
