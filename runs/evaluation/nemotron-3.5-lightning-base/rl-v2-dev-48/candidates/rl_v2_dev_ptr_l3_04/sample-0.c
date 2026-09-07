/* XDP program: Decapsulate SIT / 6in4 tunnels by popping outer IPv4 wrapper
 * and setting Ethernet type to IPv6. Forward all packets with XDP_PASS.
 *
 * Compilation: clang -target bpf -O2 -c program.c -o program.o
 * License: GPL-2.0
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

SEC("xdp")
int xdp_decapsulate_6in4(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Verify Ethernet header bounds */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Verify outer IPv4 header bounds */
	struct iphdr *outer_ip = (struct iphdr *)(eth + 1);
	if ((void *)(outer_ip + 1) > data_end)
		return XDP_PASS;

	/* Check if outer protocol is IP-in-IP (41 = IPPROTO_IPV6) */
	if (outer_ip->protocol != 41)
		return XDP_PASS;

	/* Calculate outer IPv4 header length (ihl is in 32-bit words) */
	int outer_len = (outer_ip->ihl << 2);

	/* Back up original Ethernet header */
	struct eth_hdr *saved_eth = eth;

	/* Pop the outer IPv4 header: adjust head pointer backwards */
	if (bpf_xdp_adjust_head(ctx, outer_len))
		return XDP_PASS;

	/* Restore Ethernet header after adjustment */
	eth = data;

	/* Verify updated Ethernet header bounds after adjustment */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Set Ethernet type to IPv6 (0x86DD) */
	eth->h_proto = htons(ETH_P_IPV6);

	/* Packet successfully decapsulated; forward it */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
