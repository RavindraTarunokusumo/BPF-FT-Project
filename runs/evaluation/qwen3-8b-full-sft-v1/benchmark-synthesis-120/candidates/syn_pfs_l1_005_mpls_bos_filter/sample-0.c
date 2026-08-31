#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


SEC("xdp")
int xdp_filter_syn_pfs_l1_005_mpls_bos(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    unsigned int len = (unsigned int)data + sizeof(struct ethhdr) - (unsigned int)data;
    if (len < sizeof(struct ethhdr) + 4)
        return XDP_PASS;

    unsigned char *mpls = (void *)(eth + 1);
    if ((void *)(mpls + 1) > data_end)
        return XDP_PASS;

    __u32 *label = (void *)mpls;
    if ((*label) & 0x00000100)
        return XDP_PASS;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
