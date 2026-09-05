#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_runt_frame_filter(struct xdp_md *ctx)
{
    /* Obtain pointers to packet data boundaries */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify that the Ethernet header fits within the packet bounds */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Calculate total packet wire length (from Ethernet header start to end) */
    unsigned int total_len = data_end - data;

    /* Drop runt frames: total length strictly less than 40 bytes */
    if (total_len < 40)
        return XDP_DROP;

    /* Forward all other packets */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
