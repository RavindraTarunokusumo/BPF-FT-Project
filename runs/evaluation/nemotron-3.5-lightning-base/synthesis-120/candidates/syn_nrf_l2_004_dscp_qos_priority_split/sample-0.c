#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* XDP program entry point */
SEC("xdp")
int xdp_dscp_qos_redirect(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Validate Ethernet header bounds */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic (ETH_P_IP = 0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Validate IPv4 header bounds */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Extract 6-bit DSCP from ToS field (ip->tos >> 2) */
    __u8 dscp = ip->tos >> 2;

    /* Route based on DSCP class */
    if (dscp == 46) {
        /* Expedited Forwarding (EF) -> priority interface */
        return bpf_redirect(10, 0);
    } else if (dscp == 34) {
        /* Assured Forwarding AF41 -> medium interface */
        return bpf_redirect(11, 0);
    } else {
        /* Best Effort and other DSCP values -> default interface */
        return bpf_redirect(12, 0);
    }
}

char LICENSE[] SEC("license") = "GPL";
