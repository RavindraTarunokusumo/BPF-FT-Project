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
int xdp_filter_syn_pfs_l2_008_quic_initial_short_token_drop(struct xdp_md *ctx) {
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(443))
        return XDP_PASS;

    unsigned char *quic_hdr = (void *)(udp + 1);
    if ((void *)(quic_hdr + 1) > data_end)
        return XDP_PASS;

    __u8 first_byte = quic_hdr[0];
    if ((first_byte & 0x80) != 0x80)
        return XDP_PASS;

    __u8 type = (__u8)(first_byte >> 4) & 0x03;
    if (type != 0)
        return XDP_PASS;

    if ((void *)(quic_hdr + 5) > data_end)
        return XDP_PASS;

    __u8 token_len = quic_hdr[5];
    if (token_len == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
