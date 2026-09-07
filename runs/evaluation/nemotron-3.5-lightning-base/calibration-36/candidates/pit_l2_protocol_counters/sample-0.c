/* XDP program: pit_l2_protocol_counters
 *
 * Counts IPv4 TCP, IPv4 UDP, other IPv4, and non-IPv4 packets
 * in distinct per-CPU array slots.
 *
 * Map:   protocol_counters (BPF_MAP_TYPE_PERCPU_ARRAY)
 *   key: __u32 [0=IPv4 TCP, 1=IPv4 UDP, 2=Other IPv4, 3=Non-IPv4]
 *   val: __u64 count
 *   max_entries: 4
 *
 * Action: XDP_PASS
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/* Per-CPU array map definition */
struct {
	__uint	type, BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries, 4;
	__type(key, __u32);
	__type(value, __u64);
} protocol_counters SEC(".maps");

SEC("xdp")
int xdp_protocol_counters(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct eth_hdr *eth;
	struct iphdr *ip;
	__u32 idx = 0; /* default: non-IPv4 */
	__u64 *counter;

	/* Ensure we have at least an Ethernet header */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* Check EtherType: if not IPv4, count as non-IPv4 (slot 3) */
	if (eth->h_proto != htons(ETH_P_IP)) {
		idx = 3;
	} else {
		/* IPv4: verify IPv4 header fits */
		if (data + sizeof(*eth) + sizeof(*ip) > data_end)
			return XDP_PASS;

		ip = data + sizeof(*eth);

		/* Classify by protocol */
		switch (ip->protocol) {
		case IPPROTO_TCP:
			idx = 0; /* IPv4 TCP */
			break;
		case IPPROTO_UDP:
			idx = 1; /* IPv4 UDP */
			break;
		default:
			idx = 2; /* Other IPv4 (ICMP, GRE, IGMP, etc.) */
			break;
		}
	}

	/* Increment the per-CPU counter for the selected slot */
	counter = bpf_map_lookup_elem(&protocol_counters, &idx);
	if (counter) {
		(*counter)++;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
