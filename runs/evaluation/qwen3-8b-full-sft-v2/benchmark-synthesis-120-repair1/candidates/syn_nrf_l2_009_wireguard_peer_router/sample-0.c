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
int xdp_route_syn_nrf_l2_009_wireguard_peer_router(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(51820))
        return XDP_PASS;

    unsigned char *payload = (void *)(udp + 1);
    if ((void *)(payload + 20) > data_end)
        return XDP_PASS;

    __u32 *wireguard_type = (void *)payload;
    if (*wireguard_type != 4)
        return XDP_PASS;

    __u32 *receiver_index = (void *)payload + 4;
    if ((void *)(receiver_index + 1) > data_end)
        return XDP_PASS;

    __u32 idx = *receiver_index;
    if (idx == 0x11111111)
        return bpf_redirect(25, 0);
    if (idx == 0x22222222)
        return bpf_redirect(26, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";