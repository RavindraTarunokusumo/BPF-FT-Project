/* XDP Bloom Filter IP Blocklist
 * 3-hash 4096-bit Bloom Filter using BPF_ARRAY map
 * Compiles with: clang -target bpf -O2 -c bloom_filter_xdp.c -o bloom_filter_xdp.o
 * License: GPL
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>

/* Bloom Filter Map:
 * 64 entries of 64-bit words => 4096 bits total
 * Key: __u32 word_index (0..63)
 * Value: __u64 bitmap_word (bit i set => bit i of the 4096-bit filter is set)
 */
struct {
	__uint	type, BPF_MAP_TYPE_ARRAY;
	__uint	max_entries, 64;
	__type	key, __u32;
	__type	value, __u64;
} bloom_filter SEC(".maps");

/* Hash function 1: MurmurHash3-like mix using multiplication and shift */
static __always_inline __u32 hash1(__u32 k)
{
	/* Murmur3 fmix32 */
	k ^= k >> 16;
	k *= 0x85ebca6b;
	k ^= k >> 13;
	k *= 0xc2b2ae35;
	k ^= k >> 16;
	return k;
}

/* Hash function 2: Different constant and shift pattern */
static __always_inline __u32 hash2(__u32 k)
{
	k ^= k >> 20;
	k *= 0x9e3779b9;
	k ^= k >> 24;
	k *= 0xbf58476d1ce4e5b9;
	k ^= k >> 28;
	return k;
}

/* Hash function 3: Yet another independent mix */
static __always_inline __u32 hash3(__u32 k)
{
	k ^= k >> 12;
	k *= 0x27d4eb2f;
	k ^= k >> 15;
	k *= 0x6bce69e3;
	k ^= k >> 19;
	return k;
}

/* Helper: safe lookup from bloom_filter map with bounds checking.
 * Returns 0 on success, populates *word and bit.
 * Returns 1 if index out of bounds (should not happen with correct map size).
 */
static __always_inline int lookup_word(__u32 word_index, __u64 *word)
{
	if (word_index >= 64)
		return 1;
	*word = bpf_map_lookup_elem(&bloom_filter, &word_index);
	return 0;
}

/* XDP program entry point */
SEC("xdp")
int xdp_bloom_filter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* 1. Verify we have at least an Ethernet header + IPv4 header */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Check EtherType for IPv4 (0x0800) */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 2. Verify IPv4 header fits within the packet */
	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 3. Extract source address and convert to host byte order (__u32) */
	__u32 src = bpf_ntohl(ip->saddr);

	/* 4. Compute 3 hash indices in [0, 4095] */
	__u32 h1 = hash1(src) & 0xFFF;   /* modulo 4096 */
	__u32 h2 = hash2(src) & 0xFFF;
	__u32 h3 = hash3(src) & 0xFFF;

	/* 5. Translate bit indices (0..4095) to word index (0..63) and bit offset */
	__u32 w1 = h1 >> 6;   /* h1 / 64 */
	__u32 w2 = h2 >> 6;
	__u32 w3 = h3 >> 6;
	__u64 bit1 = 1ULL << (h1 & 63);   /* h1 % 64 */
	__u64 bit2 = 1ULL << (h2 & 63);
	__u64 bit3 = 1ULL << (h3 & 63);

	/* 6. Lookup each bitmap word from the map with bounds checking */
	__u64 wval1, wval2, wval3;
	if (lookup_word(w1, &wval1))
		return XDP_PASS;   /* defensive: out-of-bounds -> pass */
	if (lookup_word(w2, &wval2))
		return XDP_PASS;
	if (lookup_word(w3, &wval3))
		return XDP_PASS;

	/* 7. Test if all 3 bits are set (bloom filter positive membership) */
	if ((wval1 & bit1) && (wval2 & bit2) && (wval3 & bit3))
		return XDP_DROP;   /* packet is in the blocklist */

	/* 8. Otherwise pass the packet */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
