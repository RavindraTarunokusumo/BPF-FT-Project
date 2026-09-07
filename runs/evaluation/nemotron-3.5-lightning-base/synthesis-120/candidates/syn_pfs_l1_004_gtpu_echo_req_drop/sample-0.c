#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* GTP-U header definition (8 bytes) */
struct gtpuhdr {
    __be16	flags_and_seq;
    __be16	teid_or_seq;
    __be16	msg_type_and_teid;
} __attribute__((packed));

/* GTP-U flags bit definitions */
#define GTPU_F_P	0x8000	/* Protocol type bit */
#define GTPU_F_P_SHIFT	15

/* XDP program entry point */
SEC("xdp")
int xdp_gtpu_echo_req_drop(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct gtpuhdr *gtpu;
	__u16 protocol;
	int eth_type;

	/* 1. Validate Ethernet frame minimum size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	eth_type = eth->h_proto;

	/* 2. Only process IPv4 (ETH_P_IP = 0x0800) */
	if (eth_type != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 3. Validate IPv4 header bounds */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);
	protocol = ip->protocol;

	/* 4. Only process UDP packets (protocol = IPPROTO_UDP = 17) */
	if (protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* 5. Validate UDP header bounds */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = data + sizeof(*eth) + sizeof(*ip);

	/* 6. Check UDP destination port is 2152 (GTP-U standard) */
	if (udp->dest != bpf_htons(2152))
		return XDP_PASS;

	/* 7. Validate total frame size for GTP-U header */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*gtpu) > data_end)
		return XDP_PASS;

	/* 8. Parse GTP-U header */
	gtpu = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);

	/* 9. Extract Message Type from GTP-U header.
	 *    GTP-U msg_type is the upper 8 bits of the 16-bit field at offset 6.
	 *    The struct layout places msg_type_and_teid at offset 6-7 (big-endian).
	 *    We read the raw 16-bit value and shift right 8 bits to get msg_type. */
	__u8 msg_type = (gtpu->msg_type_and_teid >> 8) & 0xFF;

	/* 10. Drop Echo Request (Message Type 1) */
	if (msg_type == 1)
		return XDP_DROP;

	/* 11. Pass all other cases: non-matching message types,
	 *     non-GTP-U UDP packets (already filtered by port), and truncated frames. */
	return XDP_PASS;
}

char LICENSE[] = "GPL";
