#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 
 * Histogram map: 4 bins for packet size distribution.
 * Bin 0: len < 128
 * Bin 1: 128 <= len < 512
 * Bin 2: 512 <= len < 1024
 * Bin 3: len >= 1024
 */
SEC("xdp")
int xdp_size_hist_01(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Validate that the packet data is within the mapped region.
     * This is required for verifier safety, though we only read
     * the length from the network header which is always present. */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Calculate total wire frame length. */
    int len = data_end - data;

    /* Determine the histogram bin.
     * Bin assignment:
     *   <128  -> 0
     *   128..511 -> 1
     *   512..1023 -> 2
     *   >=1024 -> 3
     */
    int bin;
    if (len < 128)
        bin = 0;
    else if (len < 512)
        bin = 1;
    else if (len < 1024)
        bin = 2;
    else
        bin = 3;

    /* Atomically increment the corresponding bin counter.
     * __sync_fetch_and_add returns the old value, but we ignore it. */
    __sync_fetch_and_add(&size_hist_01[bin], 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
