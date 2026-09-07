#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Per-CPU array map to store QUIC header type counts.
 * slot 0: Long Header packets (bit 7 == 1)
 * slot 1: Short Header packets (bit 7 == 0)
 */
struct {
	__uint	type,		/* map type */
		__uint	max_entries;	/* number of entries */
	__uint(map_flags);	/* flags, 0 for per-CPU array */
} quic_hdr_type_map SEC(".maps") = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.max_entries = 2,
};

/* XDP program entry point */
SEC("xdp")
int xdp_quic_hdr_type_counter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	__u32 *slot;
	__u64 *first_byte;
	__u8 byte_val;

	/* 1. Validate Ethernet frame boundaries */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Validate IPv4 protocol */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);

	/* 3. Validate IPv4 version and protocol (UDP = 17) */
	if (ip->version != 4 || ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* 4. Validate UDP header boundaries */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = data + sizeof(*eth) + sizeof(*ip);

	/* 5. Validate UDP port 443 (check source or destination) */
	if (udp->source != bpf_htons(443) && udp->dest != bpf_htons(443))
		return XDP_PASS;

	/* 6. QUIC payload starts right after UDP header.
	 *    Verify we have at least 1 byte of payload. */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + 1 > data_end)
		return XDP_PASS;

	first_byte = (void *)(udp + 1);

	/* 7. Read the first byte and check bit 7 (0x80) */
	byte_val = *first_byte;

	/* 8. Select per-CPU slot based on header type */
	if (byte_val & 0x80) {
		/* Long Header: Initial, Handshake, 0-RTT */
		slot = bpf_map_lookup_elem(&quic_hdr_type_map, &(__u32){0});
		if (slot)
			(*slot)++;
	} else {
		/* Short Header: 1-RTT */
		slot = bpf_map_lookup_elem(&quic_hdr_type_map, &(__u32){1});
		if (slot)
			(*slot)++;
	}

	/* 9. Always pass the packet to the network stack */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
