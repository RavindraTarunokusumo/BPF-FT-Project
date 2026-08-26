#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/icmp.h>
SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data, *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_ICMP) return XDP_PASS;
    struct icmphdr *icmp = (void *)((char *)ip + ip->ihl * 4);
    if ((void *)(icmp + 1) > data_end) return XDP_PASS;
    return (icmp->type == 8 && icmp->code == 0) ? XDP_DROP : XDP_PASS;
}
char _license[] SEC("license") = "GPL";
