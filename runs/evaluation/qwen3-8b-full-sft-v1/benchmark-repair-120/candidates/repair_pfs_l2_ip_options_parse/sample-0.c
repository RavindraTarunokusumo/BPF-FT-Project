#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    void *ip_raw = (void *)(eth + 1);
    if (ip_raw > data_end)
        return XDP_PASS;

    struct iphdr *ip = ip_raw;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->ihl < 5)
        return XDP_PASS;

    if (ip->ihl > 5) {
        __u32 ip_hdr_len = ip->ihl * 4;
        if (ip_raw + ip_hdr_len > data_end)
            return XDP_PASS;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
