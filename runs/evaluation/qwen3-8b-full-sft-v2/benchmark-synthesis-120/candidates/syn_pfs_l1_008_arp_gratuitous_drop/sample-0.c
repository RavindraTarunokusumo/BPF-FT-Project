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

struct arphdr_eth_ipv4 {
    __be16 ar_hrd;
    __u16 ar_pro;
    __u8 ar_hlen;
    __u8 ar_plen;
    __be16 ar_mhlen;
    __be16 ar_prolen;
    __be32 ar_sip;
    __be32 ar_tip;
    __u8 ar_smac[ETH_ALEN];
    __u8 ar_tmac[ETH_ALEN];
};

SEC("xdp")
int xdp_filter_syn_pfs_l1_008_arp_gratuitous_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    struct arphdr_eth_ipv4 *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return XDP_PASS;

    if (arp->ar_hrd != bpf_htons(ETH_P Ethernet))
        return XDP_PASS;

    if (arp->ar_pro != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if (arp->ar_hlen != 6 || arp->ar_plen != 4)
        return XDP_PASS;

    __be32 sip = arp->ar_sip;
    __be32 tip = arp->ar_tip;

    if (sip == tip)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
