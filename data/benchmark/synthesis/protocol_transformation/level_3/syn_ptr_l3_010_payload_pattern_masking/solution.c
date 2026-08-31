#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_payload_masking(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len <= sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    __u8 *payload = (void *)tcp + tcp_hdr_len;
    if (payload + 8 > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (payload + i + 8 > data_end)
            break;

        if (payload[i] == 'S' && payload[i+1] == 'E' && payload[i+2] == 'C' &&
            payload[i+3] == 'R' && payload[i+4] == 'E' && payload[i+5] == 'T' &&
            payload[i+6] == '9' && payload[i+7] == '9') {
            
            #pragma unroll
            for (int j = 0; j < 8; j++) {
                payload[i + j] = 'X';
            }

            tcp->check = 0;
            break;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
