#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* 
 * Per-CPU array map to store MSS histogram buckets.
 * max_entries 4 corresponds to the 4 range slots defined in the task.
 */
struct {
	__uint	type, BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries, 4;
	__uint	flags, 0;
} mss_histogram_map SEC(".maps");

/* Helper: increment the counter for a given bucket index in the per-CPU map.
 * The 'key' is the bucket index (0..3), and 'value' is the counter to increment.
 */
static __always_inline void increment_histogram(int bucket)
{
	__u64 *value;

	value = bpf_map_lookup_elem(&mss_histogram_map, &bucket);
	if (value) {
		(*value)++;
	}
}

/* XDP entry point */
SEC("xdp")
int xdp_mss_histogram(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	int tcp_opt_len;
	int mss_value = 0;
	int bucket = 0;

	/* 1. Validate Ethernet frame boundaries */
	eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* 2. Validate IPv4 protocol */
	/* We only care about IPv4; skip non-IPv4 frames */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 3. Filter only TCP protocol */
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	/* 4. Validate TCP header boundaries */
	tcp = (struct tcphdr *)(ip + 1);
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
		return XDP_PASS;

	/* 5. Filter only TCP SYN packets */
	if (!tcp->syn)
		return XDP_PASS;

	/* 6. Calculate TCP options length.
	 * tcp->doff is the offset in 32-bit words.
	 * Total TCP header size = doff * 4.
	 * Options length = total header size - standard header (20 bytes).
	 */
	tcp_opt_len = (tcp->doff * 4) - sizeof(struct tcphdr);
	if (tcp_opt_len < 0 || tcp_opt_len > data_end - (void *)(tcp + 1))
		return XDP_PASS;

	/* 7. Parse TCP options to find MSS (Kind=2, Length=4).
	 * Options are padded to 4-byte boundaries, but the MSS option
	 * is exactly 4 bytes: Kind(1) + Length(1) + Value(2) = 4 bytes.
	 * We scan the options field looking for Kind == 2 and Length == 4.
	 */
	{
		void *opt_start = (void *)(tcp + 1);
		void *opt_end = opt_start + tcp_opt_len;
		void *p = opt_start;

		while (p + 2 <= opt_end) { /* at least Kind+Length bytes */
			__u8 kind = *(__u8 *)p;
			__u8 *len_ptr = p + 1;
			__u8 length;

			if (p + 1 + 1 > opt_end)
				break;

			length = *len_ptr;

			if (kind == 2 && length == 4) {
				/* MSS option found: Kind(1) + Length(1) + MSS(2) */
				__u16 *mss_ptr = p + 2;
				if (mss_ptr + 1 <= opt_end) {
					mss_value = bpf_ntohs(*mss_ptr);

					/* 8. Bucket assignment */
					if (mss_value < 1200)
						bucket = 0;
					else if (mss_value >= 1200 && mss_value <= 1400)
						bucket = 1;
					else if (mss_value >= 1401 && mss_value <= 1460)
						bucket = 2;
					else /* MSS > 1460 */
						bucket = 3;

					increment_histogram(bucket);
				}
				/* Stop after first MSS option found */
				break;
			}

			/* Advance option pointer.
			 * Options are padded to 4-byte alignment.
			 * The total length of this option includes Kind and Length.
			 * If length < 2, we cannot reliably parse; stop.
			 */
			if (length < 2)
				break;

			/* Move past this option: Kind(1) + Length(1) + (length - 2) bytes data */
			p += 2 + (length - 2);

			/* Align to 4-byte boundary for the next option */
			if ((p - opt_start) % 4 != 0) {
				/* Add padding bytes to reach next 4-byte boundary */
				int pad = 4 - ((p - opt_start) % 4);
				p += pad;
			}

			/* Ensure we do not run past the options end */
			if (p > opt_end)
				break;
		}
	}

	/* 9. Always return XDP_PASS */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
