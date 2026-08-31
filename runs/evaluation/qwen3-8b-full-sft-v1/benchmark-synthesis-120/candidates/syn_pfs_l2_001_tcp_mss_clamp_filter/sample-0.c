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
int xdp_filter_syn_pfs_l2_001(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!tcp->syn)
        return XDP_PASS;

    unsigned int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr))
        return XDP_PASS;

    if ((void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    unsigned char *opt = (void *)tcp + sizeof(struct tcphdr);
    if (opt + 1 > (void *)tcp + tcp_hdr_len)
        return XDP_PASS;

    while (opt + 1 <= (void *)tcp + tcp_hdr_len) {
        unsigned char kind = opt[0];
        if (kind == 2) { // MSS
            if (opt + 4 <= (void *)tcp + tcp_hdr_len) {
                __u32 mss = *(unsigned int *)(opt + 1);
                if (mss > 1460)
                    return XDP_DROP;
            }
        }
        if (opt + 1 >= (void *)tcp + tcp_hdr_len)
            break;
        unsigned char opt_len = opt[1];
        if (opt + opt_len > (void *)tcp + tcp_hdr_len)
            break;
        opt += opt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
