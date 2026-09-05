#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* 
 * XDP program: classify packet length into 4 bins using an array map.
 * Bin 0: len < 128
 * Bin 1: 128 <= len < 512
 * Bin 2: 512 <= len < 1024
 * Bin 3: len >= 1024
 * Returns XDP_PASS for all frames.
 */

SEC("xdp")
int xdp_size_hist_04(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth = data;
    __u64 *counter;
    __u64 one = 1;
    __u64 len;

    /* Validate Ethernet frame boundaries */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    len = (__u64)(data_end - data);

    /* Look up the per-bin counter in the array map */
    counter = bpf_map_lookup_elem(&size_hist_04, &len, &one, BPF_ANY);
    if (!counter)
        return XDP_PASS; /* map not initialized or error */

    /* Determine bin index based on total wire frame length */
    if (len < 128)
        __sync_fetch_and_add(counter, 0); /* Bin 0 */
    else if (len < 512)
        __sync_fetch_and_add(counter, 1); /* Bin 1 */
    else if (len < 1024)
        __sync_fetch_and_add(counter, 2); /* Bin 2 */
    else
        __sync_fetch_and_add(counter, 3); /* Bin 3 */

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
