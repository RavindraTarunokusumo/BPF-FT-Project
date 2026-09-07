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
    unsigned char ar_sha[ETH_ALEN];
    __u32 ar_sip;
    unsigned char ar_tha[ETH_ALEN];
    __u32 ar_tip;
};

SEC("xdp")
int xdp_syn_nrf_l1_007_proxy_arp_responder(struct xdp_md *ctx) {
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

    if (arp->ar_op != bpf_htons(1))
        return XDP_PASS;

    if (arp->ar_tip != bpf_htonl(1921681001U))
        return XDP_PASS;

    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, "\x02\x00\x00\x00\x00\x01", ETH_ALEN);
    
    arp->ar_op = bpf_htons(2);
    __builtin_memcpy(arp->ar_sha, arp->ar_tha, ETH_ALEN);
    __builtin_memcpy(arp->ar_tha, tmp_mac, ETH_ALEN);
    __builtin_memcpy(&arp->ar_sip, &arp->ar_tip, sizeof(__u32));
    arp->ar_tip = bpf_htonl(1921681001U);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
