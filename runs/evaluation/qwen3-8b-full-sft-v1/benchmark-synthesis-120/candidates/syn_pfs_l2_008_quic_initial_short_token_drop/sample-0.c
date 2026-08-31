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
int xdp_filter_syn_pfs_l2_008_quic_initial_short_token_drop(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(443))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    if (udp->len < udp_hdr_len)
        return XDP_PASS;

    __u8 *quic_hdr = (void *)udp + udp_hdr_len;
    if ((void *)quic_hdr > data_end)
        return XDP_PASS;

    if (quic_hdr[0] & 0x80)
        return XDP_PASS;

    __u8 pkt_type = (quic_hdr[0] >> 4) & 0x0F;
    if (pkt_type != 0)
        return XDP_PASS;

    if ((void *)quic_hdr + 5 > data_end)
        return XDP_PASS;

    __u32 version = (__u32)quic_hdr[1] << 24 |
                    (__u32)quic_hdr[2] << 16 |
                    (__u32)quic_hdr[3] << 8 |
                    (__u32)quic_hdr[4];
    if (version != 0x5175636B) // "QUIC"
        return XDP_PASS;

    __u8 *dcid = quic_hdr + 5;
    if ((void *)dcid > data_end)
        return XDP_PASS;

    __u32 dcid_len = dcid[0];
    if (dcid_len < 1 || (void *)dcid + dcid_len > data_end)
        return XDP_PASS;

    __u8 *scid = dcid + 1 + dcid_len;
    if ((void *)scid > data_end)
        return XDP_PASS;

    __u32 scid_len = scid[0];
    if (scid_len < 1 || (void *)scid + scid_len > data_end)
        return XDP_PASS;

    __u8 *token_len = scid + 1 + scid_len;
    if ((void *)token_len > data_end)
        return XDP_PASS;

    if (token_len[0] == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
