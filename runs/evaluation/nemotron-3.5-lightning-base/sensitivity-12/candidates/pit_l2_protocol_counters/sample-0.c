/* XDP program: pit_l2_protocol_counters
 *
 * Counts packets per protocol category using a per-CPU array map.
 * Categories:
 *   0 - IPv4 TCP
 *   1 - IPv4 UDP
 *   2 - Other IPv4 (ICMP, GRE, IGMP, etc.)
 *   3 - Non-IPv4 (anything that is not ETH_P_IP)
 *
 * The program increments the counter for every processed packet
 * and returns XDP_PASS.
 *
 * Compilation: clang -target bpf -D__KERNEL__ -D__TARGET_ARCH_x86 \
 *                -I /usr/src/linux-headers-$(uname -r)/include \
 *                -c pit_l2_protocol_counters.c -o pit_l2_protocol_counters.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* Per-CPU array map definition.
 * Key: __u32 (0=IPv4 TCP, 1=IPv4 UDP, 2=Other IPv4, 3=Non-IPv4)
 * Val: __u64 (per-CPU counter)
 * Max entries: 4 */
struct {
	__uint	type, BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries, 4;
	__type(key, __u32);
	__type(value, __u64);
} protocol_counters SEC(".maps");

SEC("xdp")
int xdp_protocol_counters(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Validate Ethernet header */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Check EtherType */
	if (eth->h_proto != htons(ETH_P_IP)) {
		/* Non-IPv4 packet -> slot 3 */
		__u32 key = 3;
		__u64 *counter =
			bpf_map_lookup_elem(&protocol_counters, &key);
		if (counter)
			(*counter)++;
		return XDP_PASS;
	}

	/* IPv4 packet: parse IPv4 header */
	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* Determine protocol slot */
	__u32 slot;
	switch (ip->protocol) {
	case IPPROTO_TCP:
		slot = 0; /* IPv4 TCP */
		break;
	case IPPROTO_UDP:
		slot = 1; /* IPv4 UDP */
		break;
	default:
		slot = 2; /* Other IPv4 (ICMP, GRE, IGMP, etc.) */
		break;
	}

	/* Increment the per-CPU counter for the selected slot */
	__u32 key = slot;
	__u64 *counter =
		bpf_map_lookup_elem(&protocol_counters, &key);
	if (counter)
		(*counter)++;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
