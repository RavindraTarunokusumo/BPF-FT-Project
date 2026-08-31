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
int xdp_transform_syn_ptr_l3_010(struct xdp_md *ctx) {
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

    __u64 payload_start = (void *)tcp + sizeof(struct tcphdr);
    if (payload_start >= data_end)
        return XDP_PASS;

    __u8 *p = (__u8 *)payload_start;
    #pragma unroll
    for (int i = 0; i <= data_end - p; i++) {
        if (p[0] == 'S' && p[1] == 'E' && p[2] == 'C' && p[3] == 'R' &&
            p[4] == 'E' && p[5] == 'T' && p[6] == '9' && p[7] == '9') {
            #pragma unroll
            for (int j = 0; j < 8; j++)
                p[j] = 'X';
            // Invalidate checksum
            ip->check = 0;
        }
        p++;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
