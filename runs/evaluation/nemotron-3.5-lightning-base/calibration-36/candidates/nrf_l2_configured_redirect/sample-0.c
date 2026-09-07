#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <bpf/bpf_helpers.h>

/* 
 * Array map to store the forwarding interface index.
 * Key: __u32 (0)
 * Val: __u32 (ifindex)
 */
struct {
	__uint	type, BPF_MAP_TYPE_ARRAY;
	__uint	max_entries, 1;
	__type(key, __u32);
	__type(value, __u32);
} forwarding_config SEC(".maps");

SEC("xdp")
int nrf_l2_configured_redirect(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* 
	 * Check for minimum Ethernet frame size.
	 * Runts (< 14 bytes) should be passed to the host stack.
	 */
	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	struct ethhdr *eth = data;

	/* 
	 * Ensure the Ethernet header fits within the packet bounds.
	 * We check after the ethhdr struct to be safe, though the
	 * above check already guarantees this.
	 */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* 
	 * Lookup key 0 in the forwarding_config map.
	 * If the map entry is absent, bpf_map_lookup_elem returns -ENOENT
	 * and we must return XDP_ABORTED.
	 */
	__u32 key = 0;
	__u32 ifindex = 0;
	__u32 *p_ifindex;

	p_ifindex = bpf_map_lookup_elem(&forwarding_config, &key, &ifindex);
	if (!p_ifindex)
		return XDP_ABORTED;

	/* 
	 * If the resolved ifindex is 0, treat as invalid configuration.
	 * Return XDP_ABORTED as per specification.
	 */
	if (ifindex == 0)
		return XDP_ABORTED;

	/* 
	 * Redirect the frame to the configured interface index.
	 * The second argument (flags) is set to 0.
	 */
	return bpf_redirect(ifindex, 0);
}

char _license[] SEC("license") = "GPL";
