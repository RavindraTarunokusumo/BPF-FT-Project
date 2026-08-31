#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_quic_token_filter(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(443))
        return XDP_PASS;

    __u8 *quic = (void *)(udp + 1);
    if (quic + 5 > data_end)
        return XDP_PASS;

    __u8 first_byte = *quic;
    // Long Header has bit 7 set (0x80)
    if ((first_byte & 0x80) == 0)
        return XDP_PASS;

    // Packet Type is bits 4-5: (first_byte >> 4) & 0x03. Type 0 = Initial
    __u8 pkt_type = (first_byte >> 4) & 0x03;
    if (pkt_type != 0)
        return XDP_PASS;

    // Skip Version (4 bytes): offset 5
    __u8 *ptr = quic + 5;
    if (ptr + 1 > data_end)
        return XDP_PASS;

    __u8 dcid_len = *ptr;
    ptr += 1 + dcid_len;
    if (ptr + 1 > data_end)
        return XDP_PASS;

    __u8 scid_len = *ptr;
    ptr += 1 + scid_len;
    if (ptr + 1 > data_end)
        return XDP_PASS;

    // In QUIC Initial, next is Token Length (varint; 1 byte if < 64)
    __u8 token_len = *ptr;
    if (token_len == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
