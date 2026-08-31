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
int xdp_transform_syn_ptr_l1_007_arp_target_mac_rewrite(struct xdp_md *ctx) {
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

    if (arp->ar_op != bpf_htons(2))
        return XDP_PASS;

    unsigned char *tha = arp->ar_tha;
    if (tha + 6 > (void *)(eth + 1))
        return XDP_PASS;

    tha[0] = 0x02;
    tha[1] = 0xAA;
    tha[2] = 0xBB;
    tha[3] = 0xCC;
    tha[4] = 0xDD;
    tha[5] = 0xEE;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
