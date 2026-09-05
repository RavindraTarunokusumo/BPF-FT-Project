/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/errno.h>

/* XDP program entry point */
SEC("xdp")
int xdp_swap_mac(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Check that the Ethernet header fits within the packet */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* Verify we have at least 14 bytes (12 bytes MAC + 2 bytes EtherType) */
    if (data + 14 > data_end)
        return XDP_PASS;

    /* Swap MAC addresses using a temporary buffer */
    unsigned char tmp[ETH_ALEN];
    bpf_memcpy(tmp, eth->h_dest, ETH_ALEN, BPF_F_DMA);
    bpf_memcpy(eth->h_dest, eth->h_source, ETH_ALEN, BPF_F_DMA);
    bpf_memcpy(eth->h_source, tmp, ETH_ALEN, BPF_F_DMA);

    /* Preserve EtherType and payload exactly – no modification needed */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
