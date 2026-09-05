#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

/* Map to hold the size histogram.
 * 4 bins: <128, 128-511, 512-1023, >=1024 */
SEC("xdp")
int xdp_size_hist_02(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 *counter;
    __u64 len;
    int bin;

    /* Validate that the packet has at least the Ethernet header.
     * This is a safety check required by the verifier. */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Calculate the total wire frame length (Layer 2 payload). */
    len = data_end - data;

    /* Determine the bin index based on frame length. */
    if (len < 128)
        bin = 0;
    else if (len < 512)
        bin = 1;
    else if (len < 1024)
        bin = 2;
    else
        bin = 3;

    /* Atomically increment the counter for the selected bin. */
    counter = bpf_map_lookup_elem(&size_hist_2, &bin);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

/* Map definition.
 * MAP_TYPE_ARRAY with 4 entries, each entry is a __u64. */
struct {
    __uint_type__(type, BPF_MAP_TYPE_ARRAY);
    __uint_type__(size, 4);
    __uint_type__(key_size, sizeof(int));
    __uint_type__(value_size, sizeof(__u64));
    __array_type__(values, __u64, 4);
} size_hist_2 SEC(".maps");
