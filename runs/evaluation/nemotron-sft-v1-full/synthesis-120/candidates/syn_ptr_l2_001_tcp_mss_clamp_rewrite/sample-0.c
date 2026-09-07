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
int xdp_transform_syn_ptr_l2_001_tcp_mss_clamp_rewrite(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!(tcp->syn))
        return XDP_PASS;

    unsigned int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    unsigned char *opts = (void *)(tcp + 1);
    while ((void *)opts + 3 < (void *)tcp + tcp_hdr_len) {
        if (opts[0] == 2 && opts[1] == 4) {
            __u32 *mss = (__u32 *)(opts + 2);
            if (*mss > 1300) {
                *mss = bpf_htons(1300);
                // Incremental checksum adjustment
                __u32 csum = (__u32)tcp->check + (__u32)bpf_htons(0x0514) - (__u32)bpf_htons(*mss);
                while (csum >> 16)
                    csum = (csum & 0xFFFF) + (csum >> 16);
                tcp->check = (__u16)csum;
            }
        }
        unsigned int opt_len = opts[1];
        if (opt_len == 0)
            break;
        opts += opt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
