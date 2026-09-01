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
int xdp_filter_syn_pfs_l2_006_geneve_opt_critical_drop(struct xdp_md *ctx) {
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

    struct geneve_hdr *gen = (void *)(udp + 1);
    if ((void *)(gen + 1) > data_end)
        return XDP_PASS;

    if (gen->flags & GENEVE_CRITICAL)
        return XDP_DROP;

    __u32 opt_len = gen->opt_len * 4;
    if (opt_len > 0) {
        void *opt_end = (void *)gen + sizeof(*gen) + opt_len;
        if (opt_end > data_end)
            return XDP_PASS;

        __u8 *opt = (void *)gen + sizeof(*gen);
        while (opt_len > 0) {
            if ((void *)(opt + 1) > data_end)
                return XDP_PASS;

            __u16 type = *( (__u16 *)opt);
            if (type & 0x80)
                return XDP_DROP;

            opt += sizeof(__u16);
            __u16 len = *( (__u16 *)opt);
            if (len < sizeof(__u16) || (void *)opt + len > data_end)
                return XDP_PASS;

            opt += len;
            opt_len -= len;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
