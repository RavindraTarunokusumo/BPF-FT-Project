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
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->doff < sizeof(struct tcphdr)/4)
        return XDP_PASS;

    unsigned int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    unsigned char *opt = (void *)tcp + sizeof(struct tcphdr);
    if (opt + 10 > (void *)tcp + tcp_hdr_len)
        return XDP_PASS;

    // Overwrite 10 bytes with NOPs (0x01)
    __builtin_memcpy(opt, "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01", 10);

    // Recalculate TCP checksum
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        __u16 *p = (void *)tcp + i;
        csum += p[0];
        csum = (csum & 0xFFFF) + (csum >> 16);
    }
    tcp->check = ~csum + 0xFFFF;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
