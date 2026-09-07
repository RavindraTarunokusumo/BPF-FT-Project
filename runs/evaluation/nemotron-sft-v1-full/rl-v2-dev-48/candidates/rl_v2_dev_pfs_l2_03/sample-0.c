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
int xdp_filter_runt_v2_dev_pfs_l2_03(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if ((void *)(data + sizeof(__u32)) > data_end)
        return XDP_PASS;

    __u32 len = (__u32)data;

    if (len < 40)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
