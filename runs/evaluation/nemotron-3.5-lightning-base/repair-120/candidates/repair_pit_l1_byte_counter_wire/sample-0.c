#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * Per-CPU array map holding a single 64-bit counter.
 * Key 0 is used to accumulate the total wire bytes seen by this XDP program.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} byte_count SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    /* Obtain the raw packet boundaries as byte offsets from the XDP program context.
     * The casts to (void *)(long) are required to perform pointer arithmetic
     * in standard C (avoids the "arithmetic on pointers to void" error). */
    void *data   = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Calculate the packet length in bytes (wire bytes, not skb->len).
     * The subtraction of two void* pointers yields the number of bytes
     * between the two addresses. */
    __u64 byte_len = (unsigned long)data_end - (unsigned long)data;

    /* Look up the per-CPU counter at key 0 and add the packet length.
     * bpf_map_lookup_elem returns a pointer to the value stored in the map. */
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&byte_count, &key);
    if (cnt)
        *cnt += byte_len;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
