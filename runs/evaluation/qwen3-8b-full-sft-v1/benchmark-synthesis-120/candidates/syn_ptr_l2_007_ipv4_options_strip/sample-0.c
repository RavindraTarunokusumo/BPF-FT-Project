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
int xdp_transform_syn_ptr_l2_007(struct xdp_md *ctx) {
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

    if (ip->ihl != 6)
        return XDP_PASS;

    __u8 *new_data = (void *)(eth + 1) + 4;
    if (new_data > (void *)(ip + 1))
        return XDP_PASS;

    __u64 len = (__u64)data + (__u64)ip - (__u64)eth;
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) - 4)
        return XDP_PASS;

    __builtin_memcpy(new_data, eth, (void *)(ip) - (void *)eth);
    ip = new_data;
    ip->ihl = 5;
    ip->tot_len = (__u16)ip->tot_len - 4;
    // Simple incremental checksum adjustment
    __u32 csum = (__u32)ip->check + 0x01010101;
    ip->check = (__u16)csum + (csum >> 16);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
