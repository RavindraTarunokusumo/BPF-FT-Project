/* XDP program: GENEVE Option Class Histogram
 * Category: packet_inspection_telemetry
 * Difficulty: level_2
 *
 * Inspects GENEVE tunnel traffic (UDP port 6081) and tallies Option Class
 * occurrences from TLV options into a per-CPU array map.
 *
 * Slot mapping:
 *   0: Linux (0x0100)
 *   1: Open vSwitch (0x0101)
 *   2: AWS (0x0102)
 *   3: Other classes
 *
 * Always returns XDP_PASS.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* GENEVE header definition
 * https://datatracker.ietf.org/doc/html/rfc8602
 * Version: 2 bytes
 * Reserved: 2 bytes
 * Protocol Type: 2 bytes
 * Virtual Network Identifier: 4 bytes
 * Option Length: 2 bytes
 * Option: variable
 */
struct geneve_hdr {
	__be16		vni;
	__be16		opt_len;
	/* Options follow */
};

/* Ethernet + IPv4 + UDP + GENEVE helper structures */
struct eth_ip_udp_geneve {
	struct eth_hdr	eth;
	struct iphdr	ip;
	struct udphdr	udp;
	struct geneve_hdr geneve;
};

/* Map definition: per-CPU array with 4 slots */
struct {
	__uint	type, MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries, 4;
	__type(values, __u32);
} geneve_class_map SEC(".maps");

/* Helper: load a __be16 in native byte order (big-endian wire format) */
static __always_inline __u16 get_be16(const __u16 *ptr)
{
	return (__u16)bpf_ntohl((__u32)ptr);
}

/* Helper: load a __u32 in native byte order */
static __always_inline __u32 get_be32(const __u32 *ptr)
{
	return (__u32)bpf_ntohl((__u32)ptr);
}

/* XDP program entry point */
SEC("xdp")
int xdp_geneve_class_histogram(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_ip_udp_geneve *pkt;
	__u16 geneve_opt_len;
	__u16 opt_class;
	__u32 *slot;
	int i, opt_offset;

	/* 1. Validate minimal Ethernet frame size */
	if (data + sizeof(struct eth_hdr) > data_end)
		return XDP_PASS;

	pkt = data;

	/* 2. Validate IPv4 protocol */
	if (pkt->ip.protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* 3. Validate UDP destination port 6081 (GENEVE) */
	if (ntohs(pkt->udp.dport) != 6081)
		return XDP_PASS;

	/* 4. Validate GENEVE header bounds */
	if (data + sizeof(struct eth_ip_udp_geneve) > data_end)
		return XDP_PASS;

	/* 5. Read GENEVE Option Length (big-endian) */
	geneve_opt_len = get_be16(&pkt->geneve.opt_len);

	/* 6. Validate that option data fits within the packet */
	if (data + sizeof(struct eth_ip_udp_geneve) + geneve_opt_len > data_end)
		return XDP_PASS;

	/* 7. Initialize all 4 slots to zero (per-CPU map write) */
	for (i = 0; i < 4; i++) {
		slot = bpf_map_lookup_elem(&geneve_class_map, &((__u32){i}));
		if (slot) {
			*slot = 0;
		}
	}

	/* 8. Safely iterate through GENEVE TLV options */
	/* Options start right after the fixed GENEVE header (8 bytes) */
	opt_offset = sizeof(struct geneve_hdr);

	while (opt_offset + 4 <= geneve_opt_len) {
		/* Each TLV option has:
		 *   2 bytes: Option Type (including Class)
		 *   2 bytes: Option Length (length of Value field in bytes)
		 */
		__u16 *option_type_ptr = data + sizeof(struct eth_ip_udp_geneve) + opt_offset;
		__u16 *option_len_ptr  = option_type_ptr + 1;
		__u16 option_type, option_value_len;

		if (option_type_ptr + 2 > data_end ||
		    option_len_ptr + 2 > data_end)
			break;

		option_type = get_be16(option_type_ptr);
		option_value_len = get_be16(option_len_ptr);

		/* Option Class is encoded in the upper 10 bits of Option Type.
		 * Per GENEVE spec: Option Type = (Class << 10) | Sub-Type
		 */
		if (option_value_len + opt_offset + 4 > geneve_opt_len)
			break; /* not enough room for value + next TLV header */

		opt_class = option_type >> 10; /* extract class value */

		/* 9. Tally into appropriate slot */
		switch (opt_class) {
		case 0x0100: /* Linux */
			slot = bpf_map_lookup_elem(&geneve_class_map, &((__u32){0}));
			break;
		case 0x0101: /* Open vSwitch */
			slot = bpf_map_lookup_elem(&geneve_class_map, &((__u32){1}));
			break;
		case 0x0102: /* AWS */
			slot = bpf_map_lookup_elem(&geneve_class_map, &((__u32){2}));
			break;
		default:
			slot = bpf_map_lookup_elem(&geneve_class_map, &((__u32){3}));
			break;
		}

		if (slot)
			(*slot)++;

		/* Advance to next TLV option */
		opt_offset += 4 + option_value_len;
	}

	/* 10. Always return XDP_PASS */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
