#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

/* 
 * Map to store the packet payload size histogram.
 * 4 bins: <128, 128-511, 512-1023, >=1024
 */
SEC("xdp")
int xdp_size_hist_03(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Calculate total wire frame length.
     * As per requirement: total wire frame length as (ctx->data_end - ctx->data) */
    __u64 frame_len = (unsigned long)data_end - (unsigned long)data;

    /* Determine histogram bin.
     * Bin 0: len < 128
     * Bin 1: 128 <= len < 512
     * Bin 2: 512 <= len < 1024
     * Bin 3: len >= 1024
     */
    int bin;
    if (frame_len < 128)
        bin = 0;
    else if (frame_len < 512)
        bin = 1;
    else if (frame_len < 1024)
        bin = 2;
    else
        bin = 3;

    /* Atomically increment the corresponding bin counter.
     * Map 'size_hist_03' has 4 entries of type __u64. */
    __sync_fetch_and_add(&size_hist_03[bin], 1);

    return XDP_PASS;
}

char LICENSE[] = "GPL";
SEC("xdp")
struct xdp_program *xdp_prog = &((struct xdp_program){
    .prog_type = XDP,
    .license = "GPL",
    .entry = (void *)xdp_size_hist_03,
    .map_idx = 0,
});
