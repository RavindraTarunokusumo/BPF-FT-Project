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

struct geneve_hdr {
    __u32 flags;
    __u32 opt_len;
};

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

    struct geneve_hdr *gene = (void *)(udp + 1);
    if ((void *)(gene + 1) > data_end)
        return XDP_PASS;

    if (gene->flags & bpf_htons(0x8000))
        return XDP_DROP;

    unsigned int num_options = gene->opt_len;
    unsigned int option_offset = sizeof(*gene);

    while (option_offset < (unsigned int)num_options * 4) {
        if ((void *)gene + option_offset + 4 > (void *)data_end)
            break;
        
        __u32 opt_type = bpf_ntohl(*(__u32 *)(gene + option_offset)) & 0xFF000000;
        if (opt_type & 0x80000000)
            return XDP_DROP;
        
        option_offset += 4;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
