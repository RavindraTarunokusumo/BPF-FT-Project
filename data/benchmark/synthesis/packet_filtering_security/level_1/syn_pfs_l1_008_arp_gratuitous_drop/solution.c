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
int xdp_garp_filter(struct xdp_md *ctx) {
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

    if (arp->ar_hrd != bpf_htons(1) || arp->ar_pro != bpf_htons(ETH_P_IP) ||
        arp->ar_hln != ETH_ALEN || arp->ar_pln != 4)
        return XDP_PASS;

    // Gratuitous ARP has sender IP equal to target IP
    if (arp->ar_sip == arp->ar_tip)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
