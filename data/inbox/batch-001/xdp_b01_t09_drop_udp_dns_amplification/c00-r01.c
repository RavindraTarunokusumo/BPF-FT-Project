#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_dns_amp(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    // FAULT: Missing check on (void *)(udp + 1) > data_end before reading udp->source / udp->dest / udp->len
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    __u16 src = bpf_ntohs(udp->source);
    __u16 dst = bpf_ntohs(udp->dest);
    __u16 ulen = bpf_ntohs(udp->len);

    if ((src == 53 || dst == 53) && ulen > 512)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
