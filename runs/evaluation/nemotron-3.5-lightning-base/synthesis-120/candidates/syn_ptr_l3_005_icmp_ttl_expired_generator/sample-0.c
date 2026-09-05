/* XDP TTL Expired ICMP Time Exceeded Generator
 * Category: protocol_transformation
 * Difficulty: level_3
 *
 * When an incoming IPv4 packet has TTL <= 1, this program synthesizes
 * an ICMP Time Exceeded (Type 11, Code 0) response. It swaps Ethernet
 * MAC addresses, swaps IPv4 source/destination, resets TTL to 64, and
 * constructs a proper ICMP header with recomputed checksums.
 *
 * Packets with TTL > 1 or non-IPv4 traffic are passed unchanged.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/stddef.h>

/* Helper: load a 16-bit value from a pointer within a buffer,
 * performing bounds checking. Returns 0 on failure. */
static __always_inline __u16 load_u16(const void *data, int offset,
                                       int size)
{
	if (offset + 2 > size)
		return 0;
	return *(const __u16 *)(data + offset);
}

/* Helper: store a 16-bit value. */
static __always_inline void store_u16(void *data, int offset, __u16 val,
                                      int size)
{
	if (offset + 2 > size)
		return;
	*(__u16 *)(data + offset) = val;
}

/* Helper: load a 32-bit value with bounds checking. */
static __always_inline __u32 load_u32(const void *data, int offset,
                                       int size)
{
	if (offset + 4 > size)
		return 0;
	return *(const __u32 *)(data + offset);
}

/* Helper: store a 32-bit value. */
static __always_inline void store_u32(void *data, int offset, __u32 val,
                                      int size)
{
	if (offset + 4 > size)
		return;
	*(__u32 *)(data + offset) = val;
}

/* IPv4 checksum computation (one's complement sum). */
static __always_inline __u16 ip_checksum(const void *data, int len, int offset)
{
	const __u8 *ptr = data + offset;
__sum16 sum = 0;
int i;

	for (i = 0; i + 1 < len; i += 2) {
		sum += *(const __u16 *)(ptr + i);
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	if (i < len) {
		sum += ptr[i];
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return ~sum;
}

/* ICMP checksum computation. */
static __always_inline __u16 icmp_checksum(const void *data, int len)
{
	const __u8 *ptr = data;
__sum16 sum = 0;
int i;

	/* RFC 1071: include pseudo-header source/dest if needed,
	 * but for ICMP echo/reply we just checksum the ICMP data. */
	for (i = 0; i + 1 < len; i += 2) {
		sum += *(const __u16 *)(ptr + i);
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	if (i < len) {
		sum += ptr[i];
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return ~sum;
}

SEC("xdp")
int xdp_ttl_expired_responder(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	int eth_type;
	int iphdr_len;
	int ip_total_len;
	int icmp_len;
	int remaining;

	/* 1. Validate Ethernet frame boundaries. */
	if (data + sizeof(struct eth_hdr) > data_end)
		return XDP_PASS;

	eth = data;
	eth_type = ntohs(eth->h_proto);

	/* Only process IPv4. */
	if (eth_type != ETH_P_IP)
		return XDP_PASS;

	/* 2. Validate IPv4 header boundaries. */
	if (data + sizeof(struct eth_hdr) + sizeof(struct iphdr) > data_end)
		return XDP_PASS;

	ip = data + sizeof(struct eth_hdr);
	iphdr_len = ip->ihl * 4;
	if (iphdr_len < sizeof(struct iphdr) || iphdr_len > (data_end - (void *)ip))
		return XDP_PASS;

	/* 3. Check TTL <= 1. If TTL > 1, pass unchanged. */
	if (ip->ttl > 1)
		return XDP_PASS;

	/* 4. Verify there is enough room for the ICMP payload
	 * (at least the original IP total length minus header). */
	ip_total_len = ntohs(ip->tot_len);
	remaining = data_end - (void *)ip;
	if (iphdr_len > remaining)
		return XDP_PASS;

	/* We will rewrite the packet in-place from the Ethernet header
	 * onward. Ensure we have enough headroom.
	 * The new packet will be: new Ethernet header + new IPv4 header
	 * (20 bytes) + ICMP header (8 bytes) = 38 bytes minimum.
	 * We must have at least that much data from the Ethernet header
	 * forward. */
	if (remaining < sizeof(struct eth_hdr) + 20 + 8)
		return XDP_PASS;

	/* 5. Swap Ethernet MAC addresses. */
	/* src -> dst, dst -> src */
	{
		unsigned char tmp[6];
		memcpy(tmp, eth->h_source, 6);
		memcpy(eth->h_source, eth->h_dest, 6);
		memcpy(eth->h_dest, tmp, 6);
	}

	/* 6. Swap IPv4 source and destination addresses. */
	{
		__be32 tmp = ip->saddr;
		ip->saddr = ip->daddr;
		ip->daddr = tmp;
	}

	/* 7. Reset IPv4 TTL to 64 and set protocol to IPPROTO_ICMP. */
	ip->ttl = 64;
	ip->protocol = IPPROTO_ICMP;

	/* 8. Recompute IPv4 checksum. */
	ip->check = 0;
	ip->check = ip_checksum(ip, iphdr_len, 0);

	/* 9. Construct ICMP Time Exceeded header (Type 11, Code 0).
	 * ICMP header is 8 bytes: type(1), code(1), checksum(2), rest(4).
	 * We place it right after the IPv4 header. */
	{
		struct icmphdr *icmp;
		__u16 icmp_total_len;

		icmp = (struct icmphdr *)((void *)ip + iphdr_len);
		if ((void *)icmp + 8 > data_end)
			return XDP_PASS;

		/* ICMP header fields. */
		icmp->type = ICMP_TIME_EXCEEDED;
		icmp->code = ICMP_EXC_TTL;
		icmp->checksum = 0;

		/* ICMP total length = 8 bytes (header only) */
		icmp_total_len = 8;

		/* Compute ICMP checksum over the 8-byte header. */
		icmp->checksum = icmp_checksum(icmp, icmp_total_len);
	}

	/* 10. Adjust IPv4 total length to include only the ICMP header.
	 * The original total length included the original payload.
	 * We now have: IP header (20) + ICMP header (8) = 28 bytes.
	 * We must update ip->tot_len. */
	ip->tot_len = htons(20 + icmp_total_len);

	/* 11. Return synthesized TX packet. */
	return XDP_TX;
}

char _license[] = "GPL";
char _version[] = "1.0";
