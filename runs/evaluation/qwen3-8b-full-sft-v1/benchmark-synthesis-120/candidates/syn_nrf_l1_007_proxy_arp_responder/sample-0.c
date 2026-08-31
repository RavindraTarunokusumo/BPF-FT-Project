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
int xdp_proxy_arp_responder(struct xdp_md *ctx) {
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

    if (arp->ar_op != bpf_htons(ARPOP_REQUEST))
        return XDP_PASS;

    unsigned char *d = (unsigned char *)&arp->ar_tip;
    if (d[0] == 192 && d[1] == 168 && d[2] == 100 && d[3] == 1) {
        struct arphdr *new_arp = arp;
        unsigned char *tmp = new_arp->ar_sha;
        new_arp->ar_sha = new_arp->ar_tha;
        new_arp->ar_tha = tmp;
        new_arp->ar_op = bpf_htons(ARPOP_REPLY);
        // Set proxy MAC
        new_arp->ar_sha[0] = 0x02;
        new_arp->ar_sha[1] = 0x00;
        new_arp->ar_sha[2] = 0x00;
        new_arp->ar_sha[3] = 0x00;
        new_arp->ar_sha[4] = 0x00;
        new_arp->ar_sha[5] = 0x01;
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
