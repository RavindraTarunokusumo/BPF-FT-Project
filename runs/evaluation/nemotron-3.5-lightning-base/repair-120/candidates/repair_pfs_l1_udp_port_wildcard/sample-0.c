#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    /* Validate variable IPv4 header length and ensure ip is within data_end */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->ihl < 5)
        return XDP_PASS;
    if ((void *)ip + ip->ihl * 4 > data_end)
        return XDP_PASS;

    /* Verify UDP header pointer is within data_end before dereferencing */
    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Drop SSDP UDP port 1900; pass all others */
    if (udp->dest == bpf_htons(1900))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
