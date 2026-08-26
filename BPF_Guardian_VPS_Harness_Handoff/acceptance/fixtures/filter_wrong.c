#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int filter_wrong(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->ihl < 5)
        return XDP_PASS;
    __u32 ip_length = (__u32)ip->ihl * 4;
    if ((void *)ip + ip_length > data_end || ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ip_length;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    return tcp->dest == bpf_htons(80) ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
