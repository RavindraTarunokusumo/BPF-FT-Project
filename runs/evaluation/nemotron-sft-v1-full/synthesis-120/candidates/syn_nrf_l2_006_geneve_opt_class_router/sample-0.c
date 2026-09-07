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
int xdp_route_syn_nrf_l2_006_geneve_opt_class_router(struct xdp_md *ctx) {
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

    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    struct geneve_hdr *geneve = (void *)(udp + 1);
    if ((void *)(geneve + 1) > data_end)
        return XDP_PASS;

    __u16 option_len = bpf_ntohs(geneve->options_len);
    if (option_len < sizeof(*geneve) || option_len > 60)
        return XDP_PASS;

    struct option_hdr *opt = (void *)(geneve + 1);
    if ((void *)(opt + 1) > data_end)
        return XDP_PASS;

    __u8 *class_ptr = (void *)opt + 3;
    if ((void *)(class_ptr + 1) > data_end)
        return XDP_PASS;

    __u16 opt_class = bpf_ntohs(*(__u16 *)class_ptr);
    if (opt_class == 0x0100)
        return bpf_redirect(20, 0);
    if (opt_class == 0x0102)
        return bpf_redirect(21, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
