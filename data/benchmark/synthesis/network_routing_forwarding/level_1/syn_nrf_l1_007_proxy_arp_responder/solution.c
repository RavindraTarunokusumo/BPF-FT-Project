#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct arphdr_eth_ipv4 {
    __be16 ar_hrd;
    __be16 ar_pro;
    __u8   ar_hln;
    __u8   ar_pln;
    __be16 ar_op;
    __u8   ar_sha[ETH_ALEN];
    __be32 ar_sip;
    __u8   ar_tha[ETH_ALEN];
    __be32 ar_tip;
};

SEC("xdp")
int xdp_proxy_arp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    struct arphdr_eth_ipv4 *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return XDP_PASS;

    if (arp->ar_op == bpf_htons(1) && arp->ar_tip == bpf_htonl(0xC0A86401)) { // 192.168.100.1
        // Set dest MAC to sender's MAC, src MAC to 02:00:00:00:00:01
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = (i == 0) ? 0x02 : 0x00;
        }

        arp->ar_op = bpf_htons(2); // ARP Reply

        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            arp->ar_tha[i] = arp->ar_sha[i];
            arp->ar_sha[i] = (i == 0) ? 0x02 : 0x00;
        }

        __be32 target_ip = arp->ar_tip;
        arp->ar_tip = arp->ar_sip;
        arp->ar_sip = target_ip;

        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
