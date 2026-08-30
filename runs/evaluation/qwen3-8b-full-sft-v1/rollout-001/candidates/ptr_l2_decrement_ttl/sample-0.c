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
int xdp_transform_ptr_l2_decrement_ttl(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->ttl <= 1)
        return XDP_DROP;

    __u8 old_ttl = ip->ttl;
    ip->ttl -= 1;

    // Incremental checksum adjustment for TTL decrement
    __u32 csum = (__u32)ip->check + (__u32)0x0100;
    if (csum < (__u32)ip->check)
        csum += 0x1;
    ip->check = (__u16)csum;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
<|im_end|>
