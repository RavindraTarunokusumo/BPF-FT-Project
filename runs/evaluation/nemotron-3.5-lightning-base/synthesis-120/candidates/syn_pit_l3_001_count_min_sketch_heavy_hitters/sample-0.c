/* XDP Count-Min Sketch (4x256) - per-CPU array map implementation
 *
 * This program implements a Count-Min Sketch with 4 rows and 256 columns
 * (1024 cells total) stored in a per-CPU array map named 'cms_sketch_map'.
 * For every IPv4 TCP or UDP packet, it extracts the 5-tuple (src/dst IP,
 * src/dst port, protocol) and computes a flow hash. Using 4 distinct row
 * hash functions, it increments the corresponding cell in each row.
 *
 * The hash functions use different prime multipliers to ensure independence.
 * The sketch always returns XDP_PASS.
 *
 * Map layout:
 *   - max_entries: 1024 (4 rows * 256 columns)
 *   - Key: flow hash (u32) - used as index into the 1024 cells
 *   - Value: counter (u64) - per-cell count
 *
 * Compilation:  clang -target bpf -c cms_sketch_xdp.c -o cms_sketch_xdp.o
 */

#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Per-CPU array map definition.
 * max_entries = 1024 (4 rows * 256 columns)
 * Key size: 4 bytes (u32 hash)
 * Value size: 8 bytes (u64 counter)
 */
struct {
	__uint	type, BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries, 1024;
	__uint(key_size, 4);
	__uint(value_size, 8);
} cms_sketch_map SEC(".maps");

/* Hash function helpers */

/* MurmurHash3-like hash for 32-bit input.
 * Uses a different seed/prime for each of the 4 rows.
 */
static __always_inline u32 hash_u32(u32 key, u32 seed)
{
	u32 h = key;

	/* MurmurHash3 fmix */
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h + seed;
}

/* Compute 4 row indices for the Count-Min Sketch.
 * Each row uses a different seed to produce an independent hash position.
 * The column index is hash % 256.
 */
static __always_inline void compute_hash_positions(u32 flow_key,
						 u32 *row_hashes)
{
	row_hashes[0] = hash_u32(flow_key, 0x1u);
	row_hashes[1] = hash_u32(flow_key, 0x3u);
	row_hashes[2] = hash_u32(flow_key, 0x7u);
	row_hashes[3] = hash_u32(flow_key, 0xdu);
}

/* Extract 5-tuple from an IPv4 TCP or UDP packet and compute a flow hash.
 * Returns 0 if the packet is not IPv4 TCP/UDP, 1 otherwise.
 */
static __always_inline int extract_5tuple_and_hash(void *data,
						   void *data_end,
						   u32 *flow_key)
{
	struct eth_hdr *eth = data;
	void *ip_start = data + sizeof(struct eth_hdr);
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	u32 proto;
	u32 src_ip, dst_ip;
	u16 src_port, dst_port;

	/* Check minimum space for Ethernet header */
	if (ip_start + sizeof(struct eth_hdr) > data_end)
		return 0;

	/* Verify Ethernet type == IPv4 (0x0800) */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;

	ip = ip_start;
	/* Check minimum space for IPv4 header (20 bytes) */
	if ((void *)ip + sizeof(struct iphdr) > data_end)
		return 0;

	/* Verify IPv4 version */
	if (ip->version != 4)
		return 0;

	proto = ip->protocol;

	/* Only process TCP or UDP */
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return 0;

	/* Transport layer start */
	void *transport = (void *)ip + (ip->ihl * 4);
	/* Check minimum space for TCP/UDP header */
	if (transport + (proto == IPPROTO_TCP ? sizeof(struct tcphdr) :
			   sizeof(struct udphdr)) > data_end)
		return 0;

	if (proto == IPPROTO_TCP) {
		tcp = transport;
		/* Check ACK flag set (basic validity check) - optional */
		/* We extract ports regardless of flags */
		src_port = tcp->source;
		dst_port = tcp->dest;
	} else {
		udp = transport;
		src_port = udp->source;
		dst_port = udp->dest;
	}

	src_ip = ip->saddr;
	dst_ip = ip->daddr;

	/* Compute 32-bit flow key.
	 * Layout: [31:24] proto | [23:16] dst_port | [15:0] src_port
	 *          [31:24] already used, re-arrange to fit u32 nicely */
	*flow_key = ((src_ip & 0xff) << 24) |
		    ((dst_ip & 0xff) << 16) |
		    ((src_port & 0xff) << 8) |
		    (dst_port & 0xff);

	/* Simple mixing to ensure better distribution across 4 rows */
	*flow_key = *flow_key * 0x9e3779b9 + (proto << 8);

	return 1;
}

/* XDP program entry point */
SEC("xdp")
int xdp_cms_sketch(struct xdp_md *xdpmd)
{
	void *data = (void *)(long)xdp_md->data;
	void *data_end = (void *)(long)xdp_md->data_end;
	u32 flow_key;
	u32 row_hashes[4];
	int i;
	u64 *counter;
	int map_idx;

	/* Extract 5-tuple and compute flow hash */
	if (!extract_5tuple_and_hash(data, data_end, &flow_key))
		return XDP_PASS;

	/* Compute 4 independent hash positions */
	compute_hash_positions(flow_key, row_hashes);

	/* Increment the Count-Min Sketch counters.
	 * Row index = row_hashes[i] % 4
	 * Column index = row_hashes[i] % 256
	 * Global cell index = (row_index * 256) + column_index
	 * Since row_hashes[i] is already 32-bit, we use modulo arithmetic.
	 *
	 * Note: In production, we would use BPF helper bpf_map_update_elem
	 * with BPF_ANY to atomically increment. Here we directly access
	 * the per-CPU array using the computed index.
	 *
	 * The per-CPU array map 'cms_sketch_map' has 1024 entries.
	 * Index calculation: (row * 256) + (hash % 256)
	 * row is 0..3, column is 0..255
	 */

	for (i = 0; i < 4; i++) {
		u32 row = row_hashes[i] & 0x3;      /* row index: 0-3 */
		u32 col = row_hashes[i] & 0xff;     /* column index: 0-255 */
		u32 cell_idx = (row * 256) + col;   /* global index: 0-1023 */

		/* Get per-CPU pointer to the map value.
		 * BPF_MAP_TYPE_PERCPU_ARRAY: value pointer = map + key_size * cpu_id
		 * We use bpf_map_lookup_elem which returns a pointer to the
		 * per-CPU value for the current CPU.
		 */
		map_idx = cell_idx; /* key is u32 cell index */
		counter = bpf_map_lookup_elem(&cms_sketch_map, &map_idx);
		if (!counter)
			return XDP_PASS; /* map not initialized, pass through */

		/* Atomic increment of the 64-bit counter.
		 * Use BPF atomic operation for safety in concurrent environments.
		 */
		bpf_atomic64_add(1, counter);
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
