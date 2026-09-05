/* XDP telemetry program: pit_l1_total_bytes
 *
 * Category     : packet_inspection_telemetry
 * Difficulty   : level_1
 *
 * Description:
 *   Adds the observed packet wire length to a per-CPU 64-bit byte counter map
 *   and returns XDP_PASS for all frames, including truncated packets.
 *
 * Map:
 *   "total_byte_counter"   - BPF_MAP_TYPE_PERCPU_ARRAY
 *                            key   : __u32  0
 *                            val   : __u64  total_bytes
 *                            max_entries: 1
 *
 * Action:
 *   pkt_len = (void *)(long)ctx->data_end - (void *)(long)ctx->data
 *   lookup key 0 in total_byte_counter
 *   if val != NULL: *val += pkt_len
 *   return XDP_PASS
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map definition */
struct {
	__uint	type, BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries, 1;
	__type(key,   __u32);
	__type(val,   __u64);
} total_byte_counter SEC(".maps");

/* XDP entry point */
SEC("xdp")
int pit_l1_total_bytes(struct xdp_md *ctx)
{
	/* Compute packet wire length.
	 * We use (void *)(long) cast to handle 32/64-bit compatibility
	 * and avoid verifier warnings on pointer arithmetic. */
	void *data   = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 pkt_len = (void *)(long)(data_end - data);

	/* Lookup key 0 in the per-CPU array map.
	 * The return value is a pointer to the value element,
	 * or NULL if the key is not found (should not happen
	 * with max_entries=1 and key=0). */
	__u64 *counter = bpf_map_lookup_elem(&total_byte_counter, &(__u32){0});

	if (counter) {
		/* Atomically add the packet length to the per-CPU counter.
		 * Note: In XDP context we are single-threaded per-CPU,
		 * so a simple addition is safe without a spinlock. */
		*counter += pkt_len;
	}

	/* Return XDP_PASS for all frames, including truncated ones. */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
