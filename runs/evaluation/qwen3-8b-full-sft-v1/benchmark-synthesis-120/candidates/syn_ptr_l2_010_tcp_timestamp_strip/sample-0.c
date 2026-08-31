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
int xdp_transform_syn_ptr_l2_010_tcp_timestamp_strip(struct xdp_md *ctx) {
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

    unsigned int opt_len = tcp->doff * 4 - sizeof(struct tcphdr);
    if (opt_len < 10)
        return XDP_PASS;

    unsigned char *opts = (void *)tcp + sizeof(struct tcphdr);
    if ((void *)opts + opt_len > data_end)
        return XDP_PASS;

    // Look for TCP Timestamp option (Kind 8, Length 10)
    while (opt_len >= 2) {
        unsigned char *p = opts;
        if (p[0] == 8 && p[1] == 10) {
            // Overwrite with NOPs (0x01)
            __builtin_memcpy(p, "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01", 10);
            // Recalculate checksum
            __u32 csum = 0;
            #pragma unroll
            for (int i = 0; i < 10; i++)
                csum += (unsigned char)p[i];
            csum = (csum & 0xFFFF) + (csum >> 16);
            __u16 *p16 = (__u16 *)p;
            #pragma unroll
            for (int i = 0; i < 5; i++)
                p16[i] = (p16[i] & 0xFFFF0000) + (csum & 0xFFFF);
            return XDP_PASS;
        }
        opts += p[1] + 2;
        opt_len -= p[1] + 2;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
