#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/*
 * Per-CPU array map to store TCP option frequencies.
 * max_entries 4 corresponds to:
 *   slot 0: MSS (Kind 2)
 *   slot 1: Window Scale (Kind 3)
 *   slot 2: SACK Permitted (Kind 4)
 *   slot 3: Timestamp (Kind 8)
 */
struct {
	__uint	type,		BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	size,		4 * sizeof(__u64);
	__uint	pinning,	BPF_PIN_UNSPEC;
	__uint	namespace,	BPF_NET_NS_GET_CURRENT;
} tcp_options_freq_map SEC(".maps");

/* Helper: safe pointer arithmetic with bounds checking */
static __always_inline void *ptr_advance(void *ptr, int delta, int *remaining)
{
	if (delta > *remaining)
		return NULL;
	*remaining -= delta;
	return ptr + delta;
}

/* Helper: safe load of 16-bit/32-bit value from pointer */
static __always_inline __u16 load_u16(const void *ptr)
{
	return *(const __u16 *)ptr;
}

static __always_inline __u32 load_u32(const void *ptr)
{
	return *(const __u32 *)ptr;
}

static __always_inline __u16 load_u16_unaligned(const void *ptr)
{
	const __u8 *p = ptr;
	return (p[0] << 8) | p[1];
}

static __always_inline __u32 load_u32_unaligned(const void *ptr)
{
	const __u8 *p = ptr;
	return ((__u32)p[0] << 24) | ((__u32)p[1] << 16) |
	       ((__u32)p[2] << 8) | p[3];
}

static __always_inline void increment_freq(int slot)
{
	__u64 *val;

	val = bpf_map_lookup_elem(&tcp_options_freq_map, &slot);
	if (val) {
		(*val)++;
	} else {
		/* Map not yet populated; skip silently */
	}
}

static __always_inline void process_tcp_options(const struct tcphdr *tcph,
						  int options_len)
{
	int remaining = options_len;
	const struct tcphdr *opt_end = (const struct tcphdr *)
		((const char *)tcph + options_len);
	const u8 *opt_ptr = (const u8 *)(tcph + 1); /* after fixed header */
	int kind, length;

	/* TCP header minimum is 20 bytes; options start right after */
	while (opt_ptr < (const u8 *)opt_end) {
		kind = *opt_ptr;
		opt_ptr++;

		if (kind == 0) { /* EOL */
			break;
		}
		if (kind == 1) { /* NOP */
			continue;
		}

		/* For multi-byte options, read length byte */
		if (opt_ptr >= (const u8 *)opt_end) {
			break; /* no length byte available */
		}
		length = *opt_ptr;
		opt_ptr++;

		if (length < 2) {
			/* Invalid length; stop processing */
			break;
		}

		/* The length includes the Kind and Length bytes itself.
		 * Total option bytes = length. Remaining bytes to process
		 * after this option = length - 2 (kind + length). */
		int option_payload = length - 2;
		int payload_remaining = option_payload;

		/* Sanity: length must not exceed remaining options space */
		if (length > remaining) {
			break; /* option extends beyond advertised length */
		}

		/* Advance pointer past this option for next iteration */
		remaining -= length;

		/* Dispatch based on Kind */
		switch (kind) {
		case 2: /* MSS */
			if (option_payload >= 2) {
				__u16 mss;
				/* MSS is 2 bytes, big-endian in the option */
				mss = load_u16_unaligned(opt_ptr - 2);
				/* Option payload is exactly 2 bytes for MSS */
				/* We just need to record the presence */
				increment_freq(0);
			}
			break;

		case 3: /* Window Scale */
			if (option_payload >= 1) {
				increment_freq(1);
			}
			break;

		case 4: /* SACK Permitted */
			if (option_payload >= 0) {
				/* No data payload; just a flag */
				increment_freq(2);
			}
			break;

		case 8: /* Timestamp */
			if (option_payload >= 8) {
				/* Timestamp option: Kind(1) Length(1) TSval(4) TSecr(4) */
				increment_freq(3);
			}
			break;

		default:
			/* Unknown option; skip */
			break;
		}
	}
}

SEC("xdp")
int xdp_tcp_options_telemetry(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcph;
	int eth_type, ip_proto;
	int tcp_header_len, options_len;

	/* 1. Validate Ethernet frame */
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	eth_type = eth->h_proto;
	if (eth_type != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 2. Validate IPv4 header */
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	ip_proto = ip->protocol;
	if (ip_proto != IPPROTO_TCP)
		return XDP_PASS;

	/* 3. Validate TCP header */
	tcph = (struct tcphdr *)(ip + 1);
	if ((void *)(tcph + 1) > data_end)
		return XDP_PASS;

	/* TCP header length in 32-bit words; convert to bytes */
	tcp_header_len = (tcph->doff * 4);
	if (tcp_header_len < sizeof(struct tcphdr))
		return XDP_PASS;

	if ((void *)(tcph + tcp_header_len) > data_end)
		return XDP_PASS;

	/* 4. Calculate options length */
	options_len = tcp_header_len - sizeof(struct tcphdr);
	if (options_len < 0)
		return XDP_PASS;

	/* 5. Process TCP options */
	process_tcp_options(tcph, options_len);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
