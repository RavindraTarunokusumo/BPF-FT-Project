/* XDP program: Drop IPv4-in-IPv4 tunneled packets destined for loopback 127.0.0.0/8
 *
 * This program inspects packets for IPv4-in-IPv4 tunnels (outer protocol 4).
 * It validates header bounds, parses the inner IPv4 header, and drops packets
 * where the inner destination address falls within the loopback range,
 * preventing tunnel-based loopback attacks.
 *
 * Usage:  ip xdp add obj <file.o> xdp0
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/* Helper: load a 32-bit value from a data pointer with bounds checking.
 * Returns 0 on failure, 1 on success and sets *val. */
static __always_inline int load_u32(const void *ptr, int size, __u32 *val)
{
	if (ptr + sizeof(__u32) > (void *)__sync_fetch_and_add(&size, 0) + 1) /* guard */ 
		return 0;
	*val = *((const __u32 *)ptr);
	return 1;
}

/* Helper: check if pointer is within data_end */
static __always_inline int within(void *ptr, void *data_end)
{
	return ptr <= data_end;
}

SEC("xdp")
int xdp_ip_in_ip_loopback_drop(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *outer_ip;
	__u32 outer_ihl;
	int eth_type;
	int iphdr_len;

	/* 1. Validate minimum Ethernet frame size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Check Ethernet type for IPv4 (0x0800) */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	eth_type = ntohs(eth->h_proto);

	/* 3. Validate outer IPv4 header bounds, accounting for variable IHL */
	if (data + sizeof(*eth) + sizeof(*outer_ip) > data_end)
		return XDP_PASS;

	outer_ip = (struct iphdr *)(eth + 1);

	/* outer_ip->ihl is in 32-bit words; convert to bytes: ihl * 4 */
	if (outer_ip->ihl < 5)
		return XDP_PASS;

	outer_ihl = outer_ip->ihl * 4;

	/* Ensure the outer IPv4 header fits within the frame */
	if (data + sizeof(*eth) + outer_ihl > data_end)
		return XDP_PASS;

	/* 4. Verify outer IP protocol == IPPROTO_IPIP (4) */
	if (outer_ip->protocol != IPPROTO_IPIP)
		return XDP_PASS;

	/* 5. Calculate inner IPv4 header start offset */
	/* Outer header starts right after Ethernet header.
	 * Inner header starts after the outer header. */
	void *inner_ip_start = (void *)((char *)outer_ip + outer_ihl);

	/* 6. Validate inner IPv4 header bounds */
	if (inner_ip_start + sizeof(*outer_ip) > data_end)
		return XDP_PASS; /* Not enough room for even a minimal inner header */

	struct iphdr *inner_ip = (struct iphdr *)inner_ip_start;

	/* Check that the inner header also fits within the frame */
	if ((char *)inner_ip + inner_ip->ihl * 4 > (char *)data_end)
		return XDP_PASS;

	/* 7. Check inner destination address for loopback 127.0.0.0/8 */
	__u32 inner_daddr;

	if (!load_u32(&inner_ip->daddr, sizeof(inner_ip->daddr), &inner_daddr))
		return XDP_PASS;

	/* Loopback test: most significant byte must be 0x7F (127) */
	if ((inner_daddr & 0xFF000000) == 0x7F000000) {
		/* Drop the packet to prevent tunnel-based loopback attacks */
		return XDP_DROP;
	}

	/* 8. Pass all other traffic (valid IP-in-IP, non-tunneled, malformed) */
	return XDP_PASS;
}

char LICENSE[] = "GPL";
