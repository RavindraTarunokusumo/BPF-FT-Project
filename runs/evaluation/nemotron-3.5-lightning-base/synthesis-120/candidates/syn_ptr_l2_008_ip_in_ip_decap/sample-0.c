#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if.h>

/* XDP program: decapsulate IPv4-in-IPv4 tunnel packets.
 * Strips the 20-byte outer IPv4 header, preserves Ethernet MACs,
 * sets eth->h_proto to ETH_P_IP, and returns XDP_PASS.
 * Non-tunneled traffic and truncated frames are passed unchanged.
 */

SEC("xdp")
int ip_in_ip_decap(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *outer_ip;
	struct iphdr *inner_ip;

	/* 1. Validate that we have at least an Ethernet header. */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Verify minimum Ethernet frame size and that we have enough
	 *    room for the outer IPv4 header (20 bytes). */
	if (data + sizeof(*eth) + 20 > data_end)
		return XDP_PASS;

	/* 3. Validate outer IPv4 header: IHL must be 5 (20 bytes). */
	outer_ip = (struct iphdr *)(eth + 1);
	if (outer_ip->ihl != 5)
		return XDP_PASS;
	if (outer_ip->protocol != IPPROTO_IPIP)
		return XDP_PASS;

	/* 4. Validate inner IPv4 header exists after the outer header. */
	if (data + sizeof(*eth) + 20 + sizeof(*inner_ip) > data_end)
		return XDP_PASS;

	inner_ip = (struct iphdr *)((char *)outer_ip + 20);

	/* 5. Verify inner IPv4 header is within the frame bounds. */
	if ((void *)inner_ip + sizeof(*inner_ip) > data_end)
		return XDP_PASS;

	/* 6. Strip the 20-byte outer IPv4 header. */
	if (bpf_xdp_adjust_head(ctx, 20))
		return XDP_PASS;

	/* 7. After adjustment, re-validate pointers. */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	outer_ip = (struct iphdr *)(eth + 1); /* now points to what was inner IP */
	inner_ip = (struct iphdr *)((char *)outer_ip + 20);

	/* 8. Restore Ethernet MAC addresses (preserve original source/dest). */
	eth->h_source[0] = eth->h_source[0]; /* no-op, kept for clarity */
	eth->h_dest[0] = eth->h_dest[0];     /* no-op, kept for clarity */
	/* The MACs are already correct from the original frame; we simply
	 * keep them as-is. No change is needed because we only stripped
	 * the outer IP header. */

	/* 9. Set Ethernet protocol type to IPv4. */
	eth->h_proto = bpf_htons(ETH_P_IP);

	/* 10. Return XDP_PASS for all cases (tunneled or not). */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
