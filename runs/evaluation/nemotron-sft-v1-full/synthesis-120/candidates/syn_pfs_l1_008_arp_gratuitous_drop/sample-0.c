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
    __u16 ar_hrd;
    __u16 ar_pro;
    __u8 ar_hln;
    __u8 ar_pln;
    __u16 ar_op;
    __u8 ar_sha[ETH_ALEN];
    __u8 ar_sip[4];
    __u8 ar_tha[ETH_ALEN];
    __u8 ar_tip[4];
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

    if (arp->ar_hrd != bpf_htons(1))
        return XDP_PASS;

    if (arp->ar_pro != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if (arp->ar_hln != 6)
        return XDP_PASS;

    if (arp->ar_pln != 4)
        return XDP_PASS;

    if (arp->ar_sip[0] == arp->ar_tip[0] &&
        arp->ar_sip[1] == arp->ar_tip[1] &&
        arp->ar_sip[2] == arp->ar_tip[2] &&
        arp->ar_sip[3] == arp->ar_tip[3])
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
