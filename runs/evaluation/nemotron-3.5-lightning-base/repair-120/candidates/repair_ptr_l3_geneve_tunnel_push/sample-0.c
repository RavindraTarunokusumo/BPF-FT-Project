#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Verify the original packet has at least an Ethernet header. */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Save the original Ethernet header contents. */
    struct ethhdr eth_saved = *eth;

    /* Push 50 bytes of outer header space (Ethernet + IPv4 + UDP + GENEVE). */
    if (bpf_xdp_adjust_head(ctx, -50))
        return XDP_DROP;

    /* Re-read data pointers after the head adjustment. */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;

    /* Verify there is enough room for the saved Ethernet header. */
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    /* Restore the original Ethernet header. */
    *new_eth = eth_saved;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
