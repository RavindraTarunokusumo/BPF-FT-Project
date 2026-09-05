#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* XDP action return values */
#define XDP_PASS  0
#define XDP_DROP  1

/* MSS option constants */
#define TCP_MAXSEG_OPTION_KIND  2
#define TCP_MAXSEG_OPTION_LEN   4
#define TCP_MSS_CLAMP_VALUE     1460

struct xdp_mss_filter_ctx {
	__u16 mss;
};

/* Helper: load a 16-bit value from a pointer within a buffer, handling alignment */
static __always_inline __u16 load_u16(const void *ptr)
{
	const __u16 *p = ptr;
	return *p;
}

/* Helper: load a 32-bit value from a pointer within a buffer, handling alignment */
static __always_inline __u32 load_u32(const void *ptr)
{
	const __u32 *p = ptr;
	return *p;
}

/* XDP program entry point */
SEC("xdp")
int xdp_mss_filter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* 1. Validate Ethernet frame minimum size */
	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	struct ethhdr *eth = data;

	/* 2. Validate EtherType == IPv4 (0x0800) */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	/* 3. Validate IPv4 header */
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if (ip + 1 > data_end)
		return XDP_PASS;

	/* Check IPv4 IHL (Internet Header Length) - measured in 32-bit words */
	if (ip->ihl < sizeof(struct iphdr) / 4)
		return XDP_PASS;

	/* Calculate IPv4 header end pointer */
	void *ip_options_end = (void *)(ip + 1) + (ip->ihl * 4);
	if (ip_options_end > data_end)
		return XDP_PASS;

	/* 4. Validate TCP protocol */
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	/* 5. Validate TCP header - account for variable IHL */
	void *tcp_start = ip_options_end;
	if (tcp_start + sizeof(struct tcphdr) > data_end)
		return XDP_PASS;

	struct tcphdr *tcp = tcp_start;

	/* Calculate TCP header end */
	void *tcp_end = (void *)(tcp + 1) + (tcp->doff * 4);
	if (tcp_end > data_end)
		return XDP_PASS;

	/* 6. Check TCP SYN flag */
	if (!(tcp->syn))
		return XDP_PASS;

	/* 7. Bounds-check TCP options region */
	if (tcp_end > ip_options_end + (ip->ihl * 4)) {
		/* Options extend beyond IPv4 header - malformed */
		return XDP_PASS;
	}

	/* 8. Iterate through TCP options to find MSS (Kind 2, Length 4) */
	/* Options start immediately after the fixed TCP header (doff * 4) */
	void *options_start = (void *)tcp + (tcp->doff * 4);
	void *options_cur = options_start;
	void *options_end = ip_options_end; /* Same as end of IPv4 header options */

	/* Safe iteration: while we have at least 2 bytes left for Kind+Length */
	while ((options_cur + 2) <= options_end) {
		__u8 kind = load_u8(options_cur);
		__u8 length;

		/* Fetch Length byte */
		if (options_cur + 1 >= options_end)
			break;
		length = load_u8(options_cur + 1);

		/* Kind 0 (End of Options) - stop iteration */
		if (kind == 0)
			break;

		/* Kind 1 (No-Operation) - skip one byte and continue */
		if (kind == 1) {
			options_cur += 2; /* Skip Kind(1) + Length(1) */
			continue;
		}

		/* For other kinds, Length includes Kind and Length itself.
		 * Total option bytes = length. We already consumed 2 bytes (Kind+Length).
		 * Remaining data bytes = length - 2. */
		if (options_cur + length > options_end)
			break; /* Malformed option - exceeds bounds */

		/* Check if this is the MSS option (Kind == 2 && Length == 4) */
		if (kind == TCP_MAXSEG_OPTION_KIND && length == TCP_MAXSEG_OPTION_LEN) {
			/* MSS value is a 16-bit big-endian integer at options_cur + 2 */
			if (options_cur + TCP_MAXSEG_OPTION_LEN <= options_end) {
				__u16 mss = load_u16(options_cur + 2);
				/* Drop if requested MSS is strictly greater than 1460 */
				if (mss > TCP_MSS_CLAMP_VALUE)
					return XDP_DROP;
			}
			/* Whether MSS is valid or not, we pass the packet
			 * (requirement: pass if MSS <= 1460 or without MSS option) */
		}

		/* Advance cursor to next option */
		options_cur += length;
	}

	/* 9. All checks passed - pass the packet */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
