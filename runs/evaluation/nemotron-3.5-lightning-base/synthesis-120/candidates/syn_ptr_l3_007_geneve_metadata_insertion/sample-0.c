#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

struct genevehdr {
	__u8  version_type;
	__u16 protocol_type;
	__u16 vni;
	__u16 opt_len;
	__u16 reserved;
	__u32 rec_seq;
	__u32 checksum;
	__u32 rec_offset;
	__u32 rec_limit;
	__u32 rec_floor;
	__u32 rec_depth;
	__u32 reserved2;
	__u8  options[0];
};

static __always_inline struct genevehdr *
geneve_hdr(struct ethhdr *eth)
{
	return (struct genevehdr *)(eth + 1);
}

SEC("xdp")
int xdp_geneve_tlv_insert(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct genevehdr *gen;

	/* 1. Validate Ethernet frame minimum size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	/* 2. Validate IPv4 protocol */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 3. Validate IPv4 header length and protocol */
	if (ip->ihl < 5 || ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* 4. Validate UDP header and length */
	if (data + sizeof(*eth) + ip->ihl + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = (void *)ip + ip->ihl;
	if (data + sizeof(*eth) + ip->ihl + sizeof(*udp) + udp->len > data_end)
		return XDP_PASS;

	/* 5. Validate UDP destination port 6081 */
	if (udp->dest != bpf_htons(6081))
		return XDP_PASS;

	/* 6. Validate GENEVE header presence and bounds */
	if (data + sizeof(*eth) + ip->ihl + sizeof(*udp) + sizeof(*gen) > data_end)
		return XDP_PASS;

	gen = (struct genevehdr *)(udp + 1);
	if (data + sizeof(*eth) + ip->ihl + sizeof(*udp) + (void *)gen + sizeof(*gen) > data_end)
		return XDP_PASS;

	/* 7. Verify GENEVE version/type and opt_len == 0 */
	if (gen->version_type != 0x60 || gen->opt_len != 0)
		return XDP_PASS;

	/* 8. Expand packet head by 8 bytes */
	if (bpf_xdp_adjust_head(ctx, -8) != 0)
		return XDP_PASS;

	/* 9. Insert 8-byte GENEVE TLV option:
	 *    - 2 bytes: Class (0x0100)
	 *    - 1 byte : Type  (0x01)
	 *    - 1 byte : Length (0x04 = 4 bytes data)
	 *    - 4 bytes: Data (0xDEADBEEF)
	 */
	gen->opt_len = 2; /* 8 bytes total option length field */

	/* Class field (__u16, big-endian 0x0100) */
	gen->options[0] = 0x01;
	gen->options[1] = 0x00;

	/* Type field (__u8) */
	gen->options[2] = 1;

	/* Length field (__u8) */
	gen->options[3] = 4;

	/* Data field (4 bytes: 0xDEADBEEF) */
	*(unsigned int *)(gen->options + 4) = bpf_htonl(0xDEADBEEF);

	/* 10. Adjust UDP length by 8 bytes to reflect the added option */
	udp->len = bpf_ntohs(bpf_htons(udp->len) + 8);

	return XDP_PASS;
}

char LICENSE[] = "GPL";
