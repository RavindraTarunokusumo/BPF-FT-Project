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
int xdp_transform_syn_ptr_l3_010_payload_pattern_masking(struct xdp_md *ctx) {
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

    unsigned int payload_len = tcp->dest - tcp->source;
    if (payload_len < 8)
        return XDP_PASS;

    __u8 *payload = (void *)tcp + tcp->doff * 4;
    if ((void *)payload + 8 > data_end)
        return XDP_PASS;

    if (payload[0] == 'S' && payload[1] == 'E' && payload[2] == 'C' && payload[3] == 'R' &&
        payload[4] == 'E' && payload[5] == 'C' && payload[6] == 'T' && payload[7] == '9') {
        payload[0] = 'X';
        payload[1] = 'X';
        payload[2] = 'X';
        payload[3] = 'X';
        payload[4] = 'X';
        payload[5] = 'X';
        payload[6] = 'X';
        payload[7] = 'X';
        // Simple reset of checksum
        ip->check = 0;
        __u16 csum = 0;
        __u16 *p = (void *)ip + 10;
        while (p < (void *)ip + ip_hdr_len) {
            csum += *p++;
        }
        ip->check = ~csum + 0xFFFF;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
