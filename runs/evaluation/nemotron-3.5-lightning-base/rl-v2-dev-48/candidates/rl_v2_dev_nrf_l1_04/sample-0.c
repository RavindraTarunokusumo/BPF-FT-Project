#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

/* Helper to access network headers safely */
static inline void *xdp_adjust_head(void *data, void *data_end,
				    int delta)
{
	void *new_data = (void *)( (unsigned long)data + delta );

	if ( new_data > data_end )
		return NULL;

	return new_data;
}

static inline struct eth_hdr *eth_hdr(void *data)
{
	return data;
}

static inline struct iphdr *ip_hdr(void *data)
{
	return data;
}

/* XDP program entry point */
SEC("xdp")
int ttl_decrement_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;

	/* 1. Verify Ethernet header bounds */
	eth = data;
	if (data + sizeof(*eth) > data_end) {
		return XDP_PASS; /* malformed Ethernet header */
	}

	/* 2. Confirm eth->h_proto == ETH_P_IP */
	if (eth->h_proto != htons(ETH_P_IP)) {
		return XDP_PASS; /* not IPv4 */
	}

	/* 3. Verify IPv4 header bounds */
	ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
		return XDP_PASS; /* truncated IPv4 header */
	}

	/* 4. Drop packet if TTL <= 1 */
	if (ip->ttl <= 1) {
		return XDP_DROP;
	}

	/* 5. Decrement TTL */
	ip->ttl--;

	/* 6. Recalculate IPv4 header checksum */
	/* IP header checksum is in network byte order; we can use
	 * bpf_l3_csum_replace or manual addition. Since we only
	 * decremented one byte, we can adjust the checksum by adding 1
	 * (mod 2^16). The kernel helper bpf_l3_csum_diff is the safest
	 * way. */
	ip->check = bpf_l3_csum_diff(ip->check, 0, 1, 0);

	/* 7. Forward packet via XDP_TX */
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
