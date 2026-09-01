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
int xdp_syn_nrf_l1_007_proxy_arp_responder(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    struct arphdr *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return XDP_PASS;

    if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER) ||
        arp->ar_pro != bpf_htons(ETH_P_IP) ||
        arp->ar_hlen != ETH_ALEN ||
        arp->ar_pln != IP_HLEN ||
        arp->ar_op != bpf_htons(ARPOP_REQUEST))
        return XDP_PASS;

    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    eth->h_proto = bpf_htons(ETH_P_ARP);

    arp->ar_op = bpf_htons(ARPOP_REPLY);

    __be16 tmp_ip = arp->ar_tip;
    arp->ar_tip = arp->ar_sip;
    arp->ar_sip = tmp_ip;

    unsigned char new_mac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    __builtin_memcpy(eth->h_source, new_mac, ETH_ALEN);

    if (arp->ar_tip == bpf_htons(1921681001U)) {
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";