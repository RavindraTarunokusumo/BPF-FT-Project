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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn && !tcp->ack) {
        unsigned char *opt = (void *)tcp + sizeof(struct tcphdr);
        if ((void *)opt + 20 > data_end)
            return XDP_PASS;

        while (opt < (void *)tcp + sizeof(struct tcphdr) + 20) {
            if (opt[0] == 2) { // MSS
                __u32 mss = (opt[1] & 0xFF) * 256 + (opt[2] & 0xFF);
                if (mss > 1300) {
                    __u32 old = mss;
                    mss = 1300;
                    // Adjust checksum
                    __u32 csum = (__u32)tcp->check + (1300 - old);
                    while (csum >> 16)
                        csum = (csum & 0xFFFF) + (csum >> 16);
                    tcp->check = (__u16)csum;
                }
                break;
            }
            if (opt[1] < 2)
                break;
            opt += opt[1];
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
