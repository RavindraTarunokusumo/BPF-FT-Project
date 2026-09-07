#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>

/* Per-CPU array map to count ARP opcodes.
 * max_entries 2: slot 0 = ARP Requests, slot 1 = ARP Replies */
struct {
	__uint	type,		BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries,	2;
} arp_opcode_map SEC(".maps");

SEC("xdp")
int xdp_arp_opcode_counter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct arphdr *arp;

	/* Validate Ethernet frame bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* Check for ARP EtherType (0x0806) */
	if (eth->h_proto != bpf_htons(ETH_P_ARP))
		return XDP_PASS;

	/* Validate ARP header bounds */
	if (data + sizeof(*eth) + sizeof(*arp) > data_end)
		return XDP_PASS;

	arp = data + sizeof(*eth);

	/* Check opcode and increment corresponding slot */
	switch (arp->ar_op) {
	case ARPOP_REQUEST: /* 1 */
		bpf_map_update_elem(
			&arp_opcode_map, /* map */
			&(int){0},       /* key = slot 0 */
			&(int){1},       /* value = increment by 1 */
			BPF_ANY
		);
		break;
	case ARPOP_REPLY: /* 2 */
		bpf_map_update_elem(
			&arp_opcode_map,
			&(int){1},       /* key = slot 1 */
			&(int){1},
			BPF_ANY
		);
		break;
	default:
		/* Ignore other opcodes */
		break;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
