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

struct geneve_opt_hdr {
    __u16 type;
    __u16 len;
};

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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    if (udp->doff * 4 < sizeof(struct udphdr))
        return XDP_PASS;

    if (udp->protocol != IPPROTO_GENEVE)
        return XDP_PASS;

    struct genevehdr *geneve = (void *)(udp + 1);
    if ((void *)(geneve + 1) > data_end)
        return XDP_PASS;

    __u8 *opt = (void *)geneve + sizeof(struct genevehdr);
    if (opt < (void *)(geneve + 1))
        return XDP_PASS;

    while (opt < (void *)(geneve + 1)) {
        struct geneve_opt_hdr *gopt = (void *)opt;
        if (gopt->type == 0x0100) {
            __u16 *p = (__u16 *)gopt + 1;
            if (*p == bpf_htons(0x0100))
                return bpf_redirect(20, 0);
        }
        if (gopt->type == 0x0102) {
            __u16 *p = (__u16 *)gopt + 1;
            if (*p == bpf_htons(0x0102))
                return bpf_redirect(21, 0);
        }
        opt += gopt->len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";