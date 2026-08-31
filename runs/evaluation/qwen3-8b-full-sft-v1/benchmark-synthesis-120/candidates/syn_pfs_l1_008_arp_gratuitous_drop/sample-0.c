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
int xdp_filter_syn_pfs_l1_008_arp_gratuitous_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    unsigned int eth_hdr_len = sizeof(struct ethhdr);
    if ((void *)eth + eth_hdr_len > data_end)
        return XDP_PASS;

    struct arphdr *arp = (void *)eth + eth_hdr_len;
    if ((void *)(arp + 1) > data_end)
        return XDP_PASS;

    if (arp->ar_hrd != bpf_htons(1) || 
        arp->ar_pro != bpf_htons(ETH_P_IP) ||
        arp->ar_hln != 6 ||
        arp->ar_pln != 4)
        return XDP_PASS;

    unsigned int arp_hdr_len = sizeof(struct arphdr);
    if ((void *)arp + arp_hdr_len > data_end)
        return XDP_PASS;

    struct arp_hdr *arp_data = (void *)arp + arp_hdr_len;
    if ((void *)(arp_data + 1) > data_end)
        return XDP_PASS;

    __u8 *s = (void *)&arp_data->ar_sip;
    __u8 *t = (void *)&arp_data->ar_tip;
    if (s[0] == t[0] && s[1] == t[1] && s[2] == t[2] && s[3] == t[3])
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
