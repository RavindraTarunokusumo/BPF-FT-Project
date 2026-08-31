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
int xdp_route_geneve_opt_class_router(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    // Check for GENEVE header
    if (udp->dgram_len < sizeof(struct udphdr) + sizeof(struct geneve_hdr))
        return XDP_PASS;

    struct geneve_hdr *geneve = (void *)udp + udp_hdr_len;
    if ((void *)(geneve + 1) > data_end)
        return XDP_PASS;

    if (geneve->hdr_len < sizeof(struct geneve_hdr))
        return XDP_PASS;

    if ((void *)geneve + geneve->hdr_len > data_end)
        return XDP_PASS;

    if (geneve->opt_class == 0x0100)
        return bpf_redirect(20, 0);

    if (geneve->opt_class == 0x0102)
        return bpf_redirect(21, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
