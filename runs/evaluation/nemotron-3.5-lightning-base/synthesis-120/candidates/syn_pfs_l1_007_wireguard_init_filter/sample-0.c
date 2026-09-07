#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* WireGuard header constants (RFC 3948 / draft-ietf-wireguard-wireguard-protocol-03)
 * The first 4 bytes of a WireGuard packet are:
 *   Byte 0:  Message Type
 *   Byte 1:  Reserved (must be zero)
 *   Bytes 2-3: Reserved (must be zero)
 * Message Types:
 *   1 = Handshake Initiation
 *   2 = Handshake Response
 *   4 = Data
 */
#define WG_HDR_SIZE	4
#define WG_MSG_HANDSHAKE_INIT	1
#define WG_MSG_HANDSHAKE_RESP	2
#define WG_MSG_DATA		4

/* XDP program entry point */
SEC("xdp")
int wg_init_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	u16 eth_type;
	u16 ip_proto;
	u16 udp_dport;

	/* 1. Validate Ethernet frame boundaries */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	eth_type = bpf_ntohs(eth->h_proto);

	/* Only process IPv4 traffic */
	if (eth_type != ETH_P_IP)
		return XDP_PASS;

	/* 2. Validate IPv4 header boundaries */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);
	ip_proto = ip->protocol;

	/* Only process UDP */
	if (ip_proto != IPPROTO_UDP)
		return XDP_PASS;

	/* 3. Validate UDP header boundaries */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = data + sizeof(*eth) + sizeof(*ip);
	udp_dport = bpf_ntohs(udp->dest);

	/* 4. Verify UDP destination port is WireGuard (51820) */
	if (udp_dport != htons(51820))
		return XDP_PASS;

	/* 5. Validate WireGuard header bounds (first 4 bytes) */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + WG_HDR_SIZE > data_end)
		return XDP_PASS;

	/* 6. Parse and check WireGuard Message Type (first byte) */
	u8 msg_type = *((u8 *)(udp + 1)); /* udp + 1 points to the first byte after the UDP header */

	if (msg_type == WG_MSG_HANDSHAKE_INIT) {
		/* Drop Handshake Initiation packets */
		return XDP_DROP;
	}

	/* Pass all other WireGuard messages (Response, Data) and any edge cases */
	return XDP_PASS;
}

char LICENSE[] = "GPL";
SEC("xdp")
