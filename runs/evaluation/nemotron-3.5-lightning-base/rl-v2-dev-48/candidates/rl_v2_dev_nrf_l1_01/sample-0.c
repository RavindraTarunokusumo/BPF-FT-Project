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
	void *new = (void *)data + delta;

	if (new > data_end)
		return NULL;

	return new;
}

static inline struct ethhdr *eth_hdr(void *data)
{
	return data;
}

static inline struct iphdr *ip_hdr(void *data)
{
	return data;
}

/* XDP program entry point */
SEC("xdp")
int xdp_ttl_decrement(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;

	/* 1. Verify Ethernet header bounds */
	eth = eth_hdr(data);
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* 2. Confirm eth->h_proto == ETH_P_IP */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	/* 3. Verify IPv4 header bounds */
	ip = ip_hdr((void *)(eth + 1));
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	/* 4. Drop packet if TTL <= 1 */
	if (ip->ttl <= 1) {
		/* Optional: decrement before drop to keep stats consistent,
		 * but requirement says "Drop packet with XDP_DROP if ip->ttl <= 1",
		 * so we drop immediately. */
		return XDP_DROP;
	}

	/* 5. Decrement TTL */
	ip->ttl--;

	/* 6. Recalculate IPv4 header checksum (ip->check) */
	/* BPF helper: bpf_l3_csum_replace */
	/* The helper replaces a 16-bit field at a given offset within the
	 * L3 packet, updating the checksum accordingly. */
	/* Offset of the checksum field within struct iphdr is 10 (0x0A). */
	/* We replace the old value with the new value (ip->check = new_checksum)
	 * by passing the new value in the 'replace' argument. */
	bpf_l3_csum_replace(data, (void *)ip - data, ip->check, ip->check, 0);

	/* 7. Forward via XDP_TX */
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
