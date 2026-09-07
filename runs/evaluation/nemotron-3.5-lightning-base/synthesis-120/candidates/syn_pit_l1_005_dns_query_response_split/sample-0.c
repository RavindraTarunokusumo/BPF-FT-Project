#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Per-CPU array map to count DNS Queries and Responses.
 * max_entries 2: slot 0 = Queries (QR==0), slot 1 = Responses (QR==1) */
struct {
	__uint	type,		BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries,	2;
	__uint	flags,		0;
} dns_qr_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_dns_qr_counter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	__u16 dns_flags;
	__u32 *slot0, *slot1;

	/* 1. Validate Ethernet frame boundaries */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Validate IPv4 header boundaries */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = (struct iphdr *)(eth + 1);

	/* Ensure IP protocol is UDP (protocol number 17) */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* 3. Validate UDP header boundaries */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = (struct udphdr *)(ip + 1);

	/* 4. Check UDP port 53 on source or destination */
	if (udp->source != htons(53) && udp->dest != htons(53))
		return XDP_PASS;

	/* 5. Validate DNS payload boundaries */
	/* DNS header starts right after the UDP header */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(__u16) > data_end)
		return XDP_PASS;

	/* Parse the DNS header flags word (2 bytes) */
	dns_flags = *(__u16 *)(udp + 1);

	/* 6. Inspect QR bit (bit 15 / 0x8000)
	 * QR == 0 -> Query -> slot 0
	 * QR == 1 -> Response -> slot 1 */
	if (dns_flags & 0x8000) {
		/* Response */
		slot1 = bpf_map_lookup_elem(&dns_qr_map, &(__u32){1});
		if (slot1)
			(*slot1)++;
	} else {
		/* Query */
		slot0 = bpf_map_lookup_elem(&dns_qr_map, &(__u32){0});
		if (slot0)
			(*slot0)++;
	}

	/* 7. Always return XDP_PASS */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
