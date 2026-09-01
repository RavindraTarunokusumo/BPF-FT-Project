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
int xdp_filter_syn_pfs_l2_001_tcp_mss_clamp_filter(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!tcp->syn || tcp->ack)
        return XDP_PASS;

    __u32 opt_len = tcp->doff * 4 - sizeof(*tcp);
    if (opt_len < 0 || (void *)tcp + sizeof(*tcp) + opt_len > data_end)
        return XDP_PASS;

    void *opt = (void *)tcp + sizeof(*tcp);
    while (opt_len > 0) {
        struct tcphdr_opt *opt_hdr = opt;
        if ((void *)(opt_hdr + 1) > data_end)
            break;
        if (opt_hdr->kind == 2) { // MSS
            __u16 *mss = (__u16 *)(opt_hdr + 1);
            if (*mss > 1460)
                return XDP_DROP;
        }
        opt_len -= opt_hdr->len;
        opt += opt_hdr->len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
