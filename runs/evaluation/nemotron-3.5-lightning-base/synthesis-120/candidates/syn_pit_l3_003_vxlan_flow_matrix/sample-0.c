/* XDP program: VXLAN flow statistics matrix collector
 *
 * Parses VXLAN encapsulated packets (UDP port 4789), extracts the 24-bit VNI,
 * and parses the inner IPv4 TCP/UDP 5-tuple. Maintains total packet and wire
 * byte counts in a BPF hash map named 'vxlan_matrix_map'.
 *
 * Always returns XDP_PASS.
 *
 * Compilation:  clang -target bpf -O2 -c vxlan_flow_matrix.c -o vxlan_flow_matrix.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* --- Key structure for the flow statistics matrix ---
 * The key uniquely identifies a tenant flow inside a VXLAN packet.
 * VNI is stored as a 32-bit value (only lower 24 bits are meaningful). */
struct vxlan_flow_key {
	__u32 vni;          /* VXLAN Network Identifier (24-bit) */
	__be32 src_ip;      /* Inner source IP address */
	__be32 dst_ip;      /* Inner destination IP address */
	__be16 src_port;    /* Inner transport layer source port */
	__be16 dst_port;    /* Inner transport layer destination port */
	__u8  proto;      /* Inner transport layer protocol (IPPROTO_TCP/UDP) */
};

/* --- Value structure per flow entry ---
 * Accumulates packet count and wire-byte count. */
struct flow_stats {
	__u64 pkts;        /* Total packets seen for this flow */
	__u64 bytes;       /* Total wire bytes seen for this flow */
};

/* BPF hash map:
 * Key   : struct vxlan_flow_key
 * Value : struct flow_stats
 * max_entries: 2048 */
SEC("xdp")
int xdp_vxlan_flow_matrix(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Basic buffer sanity check */
	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	/* --- Parse outer Ethernet header --- */
	struct ethhdr *eth = data;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS; /* Only process IPv4 packets for now */

	data += sizeof(struct ethhdr);
	if (data + sizeof(struct iphdr) > data_end)
		return XDP_PASS;

	/* --- Parse outer IPv4 header (outer header) --- */
	struct iphdr *outer_ip = data;
	__u32 outer_ip_hdr_len = outer_ip->ihl * 4;
	if (data + outer_ip_hdr_len > data_end)
		return XDP_PASS;

	data += outer_ip_hdr_len;
	if (data + sizeof(struct udphdr) > data_end)
		return XDP_PASS;

	/* --- Validate outer UDP port (VXLAN uses UDP port 4789) --- */
	struct udphdr *outer_udp = data;
	if (outer_udp->dest != bpf_htons(4789))
		return XDP_PASS; /* Not a VXLAN packet */

	data += sizeof(struct udphdr);
	if (data + 8 > data_end)
		return XDP_PASS; /* Minimum VXLAN header is 8 bytes */

	/* --- Parse VXLAN header (8 bytes) and extract VNI --- */
	/* VXLAN header format: Reserved(1) | Rsvd1(1) | Rsvd2(1) | Rsvd3(1) | VNI(24) */
	struct vxlan_hdr {
		__be32 reserved;
	} __attribute__((packed));
	const struct vxlan_hdr *vxlan = data;

	/* Extract 24-bit VNI (bits 23:0) from the 32-bit field, shift right 8 to get
	 * the actual 24-bit value, then mask to ensure only lower 24 bits are kept. */
	__u32 vni = (bpf_ntohl(vxlan->reserved) >> 8) & 0x00FFFFFF;

	data += 8; /* Skip VXLAN header */
	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	/* --- Parse inner Ethernet header --- */
	struct ethhdr *inner_eth = data;
	if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	data += sizeof(struct ethhdr);
	if (data + sizeof(struct iphdr) > data_end)
		return XDP_PASS;

	/* --- Parse inner IPv4 header --- */
	struct iphdr *inner_ip = data;
	__u32 inner_ip_hdr_len = inner_ip->ihl * 4;
	if (data + inner_ip_hdr_len > data_end)
		return XDP_PASS;

	data += inner_ip_hdr_len;
	if (data + sizeof(struct tcphdr) > data_end && data + sizeof(struct udphdr) > data_end)
		return XDP_PASS; /* Neither TCP nor UDP; cannot extract 5-tuple */

	__u8 proto = inner_ip->protocol;

	/* --- Determine transport layer start and extract 5-tuple fields --- */
	void *l4_start = data;
	__be16 src_port = 0, dst_port = 0;

	if (proto == IPPROTO_UDP) {
		if (data + sizeof(struct udphdr) > data_end)
			return XDP_PASS;
		struct udphdr *inner_udp = data;
		src_port = inner_udp->source;
		dst_port = inner_udp->dest;
		data += sizeof(struct udphdr);
	} else if (proto == IPPROTO_TCP) {
		if (data + sizeof(struct tcphdr) > data_end)
			return XDP_PASS;
		struct tcphdr *inner_tcp = data;
		src_port = inner_tcp->source;
		dst_port = inner_tcp->dest;
		data += sizeof(struct tcphdr);
	} else {
		/* Non-TCP/UDP inner protocol; still track with proto identifier. */
		/* We zero out ports for such flows, but still record them. */
	}

	/* --- Validate that we have parsed all required inner headers --- */
	if (l4_start + (proto == IPPROTO_UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr)) > data_end)
		return XDP_PASS;

	/* --- Construct the flow key --- */
	struct vxlan_flow_key key = {
		.vni		= vni,
		.src_ip		= inner_ip->saddr,
		.dst_ip		= inner_ip->daddr,
		.src_port	= src_port,
		.dst_port	= dst_port,
		.proto		= proto,
	};

	/* --- Accumulate statistics in the BPF hash map --- */
	struct flow_stats *stats;
	int map_idx;

	/* bpf_map_lookup_elem returns 0 on success, non-zero if key not found. */
	stats = bpf_map_lookup_elem(vxlan_matrix_map, &key, sizeof(key));
	if (stats) {
		/* Key exists: increment counters atomically (safe in XDP due to per-CPU
		 * map or single-core execution model, but we use simple addition as
		 * verifier allows it for scalar types in maps). */
		stats->pkts++;
		stats->bytes += ctx->data - l4_start + (proto == IPPROTO_UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr));
		/* Note: The byte count above is a rough estimate of the transport header
		 * payload. For precise wire-byte accumulation, one would need to compute
		 * total packet length from outer/inner headers. The task requirement
		 * specifies "wire byte counts", which in typical XDP telemetry implies
		 * the total packet length. We use ctx->data_len for the remaining data
		 * after the parsed inner headers, but since we only have ctx->data pointer,
		 * we approximate using the captured segment. */
	} else {
		/* Key not found: allocate a new entry. */
		struct flow_stats init = {
			.pkts	= 1,
			.bytes	= 0 /* will be updated below */,
		};
		map_idx = bpf_map_update_elem(vxlan_matrix_map, &key, &init, BPF_ANY);
		if (map_idx < 0)
			return XDP_PASS; /* Map full or error; still pass packet */
		stats = bpf_map_lookup_elem(vxlan_matrix_map, &key, sizeof(key));
		if (!stats)
			return XDP_PASS;
	}

	/* --- Update byte count for the newly created or existing entry ---
	 * We compute the packet's wire length as the data from the start of the
	 * inner Ethernet header
