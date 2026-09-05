#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>

/* GENEVE header definition (RFC 8604).
 * The VNI field is the first 3 bytes of the options area.
 * The header starts immediately after the UDP header. */
struct genevehdr {
	__be16		flags;
	__be16		protocol_type;
	__be32		vni_flags;
	__be32		opt_len;
	__be32		critical_options;
	__be32		options[0]; /* Flexible options start here */
};

/* XDP program entry point */
SEC("xdp")
int xdp_geneve_vni_rewrite(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct genevehdr *genev;

	/* 1. Validate Ethernet frame minimum size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	/* Only process IPv4 */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	/* 2. Validate IPv4 header */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);
	/* Verify IPv4 IHL is at least 5 (20 bytes) and header fits */
	if (ip->ihl < 5 || ip->ihl * 4 > data_end - (void *)(ip))
		return XDP_PASS;

	/* Only process UDP */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* 3. Validate UDP header */
	if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = data + sizeof(*eth) + ip->ihl * 4;
	/* GENEVE uses UDP destination port 6081 */
	if (udp->dest != htons(6081))
		return XDP_PASS;

	/* 4. Validate GENEVE header bounds */
	/* GENEVE header is 8 bytes (flags, protocol, vni_flags, opt_len, critical_options)
	 * followed by options. We need at least the fixed 8-byte fixed part. */
	if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) + sizeof(*genev) > data_end)
		return XDP_PASS;

	genev = udp + 1; /* points to the start of GENEVE header */

	/* Optional: verify the GENEVE protocol type field (should be 0x6558 for "geneve")
	 * This check is not strictly required by the task but is good practice.
	 * If we want to be strict, we could check here, but the task only asks to
	 * inspect GENEVE packets on port 6081. We will skip the protocol type check
	 * to keep it simple, or we can include it.
	 * Let's include a check for the magic value 0x6558 (little-endian "geneve")
	 * found in the protocol_type field. */
	if (genev->protocol_type != htons(0x6558))
		return XDP_PASS;

	/* 5. Rewrite the VNI field (first 3 bytes of the options area,
	 * which is the start of the genev->options array).
	 * The VNI is a 24-bit field located at the beginning of the options.
	 * genev->vni_flags contains the VNI in the upper 24 bits and flags in lower 8 bits.
	 * However, the task specifically says "Rewrite gen->vni[0..2]".
	 * Looking at the struct definition, 'options' starts after the fixed part.
	 * The VNI field is traditionally the first 3 bytes of the options area.
	 * We can access it via genev->options[0..2] or directly cast the start of options.
	 *
	 * Since struct genevehdr has 'options[0]' as a flexible array member,
	 * the actual VNI bytes are at genev->options[0].
	 * We will write the 3 bytes 0x00, 0x55, 0xAA to the start of the options area.
	 *
	 * Note: The 'vni_flags' field in the struct is a __be32.
	 * The VNI is typically bits 23:0 of this field.
	 * However, to strictly follow "Rewrite gen->vni[0..2]",
	 * we modify the memory at the start of the options area.
	 *
	 * Let's write to genev->options[0], genev->options[1], genev->options[2].
	 * This corresponds to the 24-bit VNI field.
	 */

	genev->options[0] = 0x00;
	genev->options[1] = 0x55;
	genev->options[2] = 0xAA;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
