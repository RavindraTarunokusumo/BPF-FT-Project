#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct coaphdr {
    __u8 ver_t_tkl;
    __u8 code;
    __be16 msg_id;
};

SEC("xdp")
int xdp_coap_filter(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(5683))
        return XDP_PASS;

    struct coaphdr *coap = (void *)(udp + 1);
    if ((void *)(coap + 1) > data_end)
        return XDP_PASS;

    // Type field is bits 4-5 of the first byte: (ver_t_tkl >> 4) & 0x03
    __u8 type = (coap->ver_t_tkl >> 4) & 0x03;
    if (type == 1) // 1 = NON (Non-confirmable)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
