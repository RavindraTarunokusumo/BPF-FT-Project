#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * Per-CPU array histogram: 16 buckets, each bucket holds a 64-bit counter.
 * Map type PERCPU_ARRAY ensures each CPU has its own independent counter
 * without needing explicit locking.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 16);
} byte_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/*
	 * Validate that at least one byte exists in the packet.
	 * The verifier requires data + 1 <= data_end before any read
	 * past the start of the mapped region.
	 */
	if (data + 1 > data_end)
		return XDP_PASS;

	/* Safe: we know data[0] exists because of the check above. */
	__u8 first_byte = *(__u8 *)data;

	/* Bucket index must be in range [0, 15]. */
	__u32 key = first_byte & 15;

	/* Look up the per-CPU counter for this bucket and increment it. */
	__u64 *cnt = bpf_map_lookup_elem(&byte_hist, &key);
	if (cnt)
		*cnt += 1;

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
