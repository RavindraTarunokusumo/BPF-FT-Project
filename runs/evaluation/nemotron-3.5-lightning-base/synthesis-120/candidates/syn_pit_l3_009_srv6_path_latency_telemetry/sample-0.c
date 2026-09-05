/* XDP program for SRv6 path latency telemetry
 *
 * Inspects SRv6 Segment Routing traffic (IPv6 Next Header 43, Routing Type 4).
 * Computes a path hash across the active Segment List (128-bit IPv6 SIDs).
 * Maintains telemetry metrics in a BPF hash map named 'srv6_path_map'.
 * Always returns XDP_PASS.
 *
 * Compilation:  clang -target bpf -O2 -c srv6_path_latency_telemetry.c -o srv6_path_latency_telemetry.o
 */

#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* --- Data Structures --- */

/* Per-path telemetry metrics stored in the BPF hash map */
struct path_metrics {
	__u64 pkts;    /* Total packets seen on this path */
	__u64 bytes;   /* Total byte volume seen on this path */
	__u32 hops;    /* Number of active SIDs (SRH->last_entry + 1) */
	__u32 pad;     /* Padding to align to 8 bytes (struct size = 32 bytes) */
};

/* BPF hash map keyed by 32-bit path hash */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct path_metrics);
} srv6_path_map SEC(".maps");

/* --- Helper Macros and Inline Functions --- */

/* Rotate left 32-bit value */
static __always_inline __u32 rotl32(__u32 x, __u8 r)
{
	return (x << r) | (x >> (32 - r));
}

/* MurmurHash3-like mix for 32-bit */
static __always_inline __u33 fmix32(__u32 h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

/* Compute 32-bit hash over an array of 128-bit SIDs.
 * srh points to the SRH; num_sids is the count of SIDs (last_entry + 1).
 * Returns a __u32 hash suitable for use as key in srv6_path_map.
 */
static __always_inline __u32 hash_sid_list(const struct ipv6_sr_hdr *srh, __u8 num_sids)
{
	__u32 h1 = 0x31415927; /* seed */
	__u32 h2 = 0xbf71552d; /* seed */
	__u32 h3 = 0x9e3779b9; /* seed */
	__u32 c1 = 0x23456789;
	__u32 c2 = 0x9abcdef1;
	const __u8 *sids = (const __u8 *)srh;
	int i, j;

	/* Iterate over each 128-bit SID */
	for (i = 0; i < num_sids; i++) {
		const __u8 *sid = sids + (i * 16);

		/* Process 4 x 32-bit words per SID */
		for (j = 0; j < 4; j++) {
			__u32 k1 = bpf_ntohl(*(__be32 *)(sid + (j * 4)));

			/* Murmur3 finalization steps */
			k1 *= c1;
			k1 = rotl32(k1, 15);
			k1 *= c2;

		h1 ^= k1;
			h1 = rotl32(h1, 17);
			h1 = h1 * 5 + 0xe6546b64;

			h2 ^= k1;
			h2 = rotl32(h2, 17);
			h2 = h2 * 5 + 0xe6546b64;

			h3 ^= k1;
			h3 = rotl32(h3, 17);
			h3 = h3 * 5 + 0xe6546b64;
		}
	}

	/* Final mix */
	h1 ^= h2;
	h1 ^= h3;
	h3 ^= h1;

	/* Return top 32 bits of the 64-bit mix as our path hash */
	return fmix32(h1);
}

/* --- XDP Program Entry --- */

SEC("xdp")
int srv6_path_latency_telemetry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct ipv6_hdr *ip6;
	struct ipv6_sr_hdr *srh;
	__u32 path_hash;
	struct path_metrics *metrics;
	__u64 bytes_count;
	__u32 nh_off;
	int srh_len;
	__u8 num_sids;

	/* --- 1. Basic Ethernet and IPv6 header validation --- */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	/* Only process IPv6 packets */
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return XDP_PASS;

	if (data + sizeof(*eth) + sizeof(*ip6) > data_end)
		return XDP_PASS;

	ip6 = data + sizeof(*eth);

	/* Check for IPv6 Next Header 43 (Routing) */
	if (ip6->nexthdr != IPPROTO_ROUTING)
		return XDP_PASS;

	/* --- 2. Validate and parse SRH (Segment Routing Header) --- */
	/* IPv6 routing header is variable length.
	 * The header format (RFC 8752) is:
	 *   Next Header (1 byte) - already verified as 43
	 *   Header Length (1 byte) - in units of 8 octets minus 8
	 *   Enabled (1 byte)
	 *   Pending (1 byte)
	 *   Reserved (1 byte)
	 *   Segments (variable, in 128-bit units)
	 *
	 * Header Length field value = K, where total header size = 8 * (K + 1) bytes.
	 * We need at least the fixed part (6 bytes) plus segments.
	 */
	if (data + sizeof(*eth) + sizeof(*ip6) + sizeof(*srh) > data_end)
		return XDP_PASS;

	srh = (struct ipv6_sr_hdr *)(ip6 + 1);
	nh_off = (void *)srh - data;

	/* Basic sanity: header length must be at least 6 (fixed part) */
	if (srh->hdr_len < 6)
		return XDP_PASS;

	srh_len = 8 * (srh->hdr_len + 1); /* total SRH bytes */
	if (nh_off + srh_len > data_end)
		return XDP_PASS;

	/* --- 3. Determine active Segment List length ---
	 * In SRv6, the "Last Entry" field (srh->last_entry) indicates the index
	 * of the last active segment. The number of active SIDs is last_entry + 1.
	 * If last_entry is 0xFF (255), all segments are active.
	 */
	if (srh->last_entry == 0xFF)
		num_sids = 256; /* all segments active */
	else
		num_sids = srh->last_entry + 1;

	/* Sanity: we need at least one SID */
	if (num_sids == 0)
		return XDP_PASS;

	/* --- 4. Compute path hash over the active SID list --- */
	path_hash = hash_sid_list(srh, num_sids);

	/* --- 5. Update BPF hash map telemetry --- */
	metrics = bpf_map_lookup_elem(&srv6_path_map, &path_hash);
	if (metrics) {
		/* Path exists: accumulate */
		metrics->pkts++;
		bytes_count = (__u64)ctx->data_end - (__u64)ctx->data;
		metrics->bytes += bytes_count;
		metrics->hops = num_sids;
	} else {
		/* New path: initialise */
		struct path_metrics init = {
			.pkts	= 1,
			.bytes	= (__u64)ctx->data_end - (__u64)ctx->data,
			.hops	= num_sids,
			.pad	= 0,
		};

		bpf_map_update_elem
