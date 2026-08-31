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
int xdp_transform_ptr_l3_tcp_dnat(struct xdp_md *ctx) {
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

    __u8 *d = (void *)&ip->daddr;
    if (d[0] == 0xC0 && d[1] == 0xA8 && d[2] == 0x64 && d[3] == 0x32) {
        return XDP_PASS;
    }

    __u32 old_daddr = ip->daddr;
    ip->daddr = bpf_htonl(0xC0A86432);

    // Incremental checksum adjustment for DNAT
    __u32 csum = (__u32)ip->check + (__u32)d[0] - (__u32)old_daddr;
    csum += (__u32)d[1] - (__u32)(old_daddr >> 8);
    csum += (__u32)d[2] - (__u32)(old_daddr >> 16);
    csum += (__u32)d[3] - (__u32)(old_daddr >> 24);
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = (__u16)csum;

    __u16 old_dest = tcp->dest;
    tcp->dest = bpf_htons(8080);

    // Incremental checksum adjustment for port change
    __u16 *p = (__u16 *)tcp + 2;
    __u32 csum = (__u32)*p + (__u32)8080 - (__u32)old_dest;
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    *p = (__u16)csum;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
