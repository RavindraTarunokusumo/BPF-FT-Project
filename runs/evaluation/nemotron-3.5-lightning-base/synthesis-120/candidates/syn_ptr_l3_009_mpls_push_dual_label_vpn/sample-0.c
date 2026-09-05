#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Outer MPLS label 1000 (BOS=0, TTL=64) */
#define MPLS_OUTER_LABEL 1000
/* Inner VPN Service Label 200 (BOS=1, TTL=64) */
#define MPLS_INNER_LABEL 200

SEC("xdp")
int xdp_mpls_push_dual_label(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;

	/* 1. Validate Ethernet frame bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Verify EtherType is IPv4 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 3. Validate IPv4 header bounds */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = (struct iphdr *)(eth + 1);

	/* 4. Expand packet head by 8 bytes for the MPLS label stack */
	if (bpf_xdp_adjust_head(ctx, -8) != 0)
		return XDP_PASS;

	/* 5. Update Ethernet header pointer after adjustment */
	eth = data;
	ip = (struct iphdr *)(eth + 1);

	/* 6. Push outer MPLS label (BOS=0, TTL=64) */
	/* MPLS label format: 20 bits label, 3 bits BOS, 1 bit S */
	/* Outer label: label=1000, BOS=0 => value = 1000 << 1 = 0xFA0 */
	/* After adjustment, eth points to the new start; we write before IP header */
	*(uint32_t *)(ip - 1) = bpf_htonl((MPLS_OUTER_LABEL << 1) | 0); /* BOS=0 */

	/* 7. Push inner VPN Service Label (BOS=1, TTL=64) */
	/* Inner label sits right after outer label (8 bytes total) */
	/* Inner label: label=200, BOS=1 => value = (200 << 1) | 1 = 0x101 */
	*(uint32_t *)(ip - 1 + 4) = bpf_htonl((MPLS_INNER_LABEL << 1) | 1); /* BOS=1 */

	/* 8. Set eth->h_proto to 0x8847 (MPLS over Ethernet) */
	eth->h_proto = bpf_htons(0x8847);

	/* 9. Decrement TTL on the inner IPv4 header (standard MPLS penultimate hop behavior) */
	/* The inner packet's TTL is at ip->ttl; we set it to 64 as required */
	ip->ttl = 64;

	/* 10. Return XDP_PASS as mandated */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
