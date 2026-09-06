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

    unsigned int ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!(tcp->syn))
        return XDP_PASS;

    unsigned int tcp_hlen = tcp->doff * 4;
    if (tcp_hlen < sizeof(*tcp) || (void *)tcp + tcp_hlen > data_end)
        return XDP_PASS;

    unsigned int opt_len = tcp_hlen - sizeof(*tcp);
    if (opt_len > 60)
        return XDP_PASS;

    unsigned int i = 0;
    while (i < opt_len) {
        if (i + 2 > opt_len)
            break;
        __u8 kind = tcp->options[i];
        if (kind == 2) {
            if (i + 4 > opt_len)
                break;
            __u32 mss = bpf_ntohl(*(__u32 *)(tcp->options + i + 2));
            if (mss > 1460)
                return XDP_DROP;
        }
        i += 4;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
