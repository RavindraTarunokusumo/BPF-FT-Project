/* XDP Dual-Path Gateway Balancer
 *
 * Directs even hashes to Gateway A and odd to Gateway B.
 * Forwards all other traffic with XDP_PASS.
 *
 * Technical Specifications:
 *  - Verifies Ethernet and IPv4 header bounds against data_end
 *  - Confirms eth->h_proto == ETH_P_IP
 *  - Computes 2-tuple XOR hash: (ip->saddr ^ ip->daddr)
 *  - LSB == 0  -> set eth->h_dest to 52:54:00:00:00:0a (Gateway A)
 *  - LSB == 1  -> set eth->h_dest to 52:54:00:00:00:0b (Gateway B)
 *  - Returns XDP_TX for routed packets, XDP_PASS for non-IP traffic
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* Helper macro to safely load a 32-bit value from a pointer
 * within the packet buffer, returning 0 on failure. */
#define LOAD_U32(ptr) ({				\
	u32 __val = 0;				\
	if ((void *)(ptr) + sizeof(__val) > data_end) \
		__val = 0;				\
	else					\
		__val = *((u32 *)(ptr));		\
	__val;					\
})

SEC("xdp")
int xdp_dual_path_balancer(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;

	/* 1. Verify Ethernet header bounds */
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* 2. Confirm eth->h_proto == ETH_P_IP */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	/* 3. Verify IPv4 header bounds */
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	/* 4. Compute 2-tuple XOR hash: (ip->saddr ^ ip->daddr) */
	u32 src = LOAD_U32(&ip->saddr);
	u32 dst = LOAD_U32(&ip->daddr);
	u32 xor_hash = src ^ dst;

	/* 5. Direct based on LSB of XOR hash */
	if (xor_hash & 1) {
		/* LSB is 1 -> Gateway B */
		eth->h_dest[0] = 0x52;
		eth->h_dest[1] = 0x54;
		eth->h_dest[2] = 0x00;
		eth->h_dest[3] = 0x00;
		eth->h_dest[4] = 0x00;
		eth->h_dest[5] = 0x0b;
	} else {
		/* LSB is 0 -> Gateway A */
		eth->h_dest[0] = 0x52;
		eth->h_dest[1] = 0x54;
		eth->h_dest[2] = 0x00;
		eth->h_dest[3] = 0x00;
		eth->h_dest[4] = 0x00;
		eth->h_dest[5] = 0x0a;
	}

	/* 6. Return XDP_TX for routed packets */
	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
