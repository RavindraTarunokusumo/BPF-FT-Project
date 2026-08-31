#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct genevehdr {
    __u8 opt_len:6;
    __u8 ver:2;
    __u8 rsvd1:6;
    __u8 critical:1;
    __u8 oam:1;
    __be16 proto_type;
    __u8 vni[3];
    __u8 reserved2;
};

struct geneve_opt {
    __be16 opt_class;
    __u8 type;
    __u8 flags_length; // rsvd:3, length:5 (in 4-byte multiples)
};

SEC("xdp")
int xdp_geneve_crit_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    struct genevehdr *gen = (void *)(udp + 1);
    if ((void *)(gen + 1) > data_end)
        return XDP_PASS;

    if (gen->critical) // Global critical flag in base header
        return XDP_DROP;

    int opt_len_bytes = gen->opt_len * 4;
    if (opt_len_bytes == 0)
        return XDP_PASS;

    void *opts_start = (void *)(gen + 1);
    void *opts_end = opts_start + opt_len_bytes;
    if (opts_end > data_end)
        return XDP_PASS;

    __u8 *ptr = opts_start;

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (ptr + sizeof(struct geneve_opt) > opts_end || ptr + sizeof(struct geneve_opt) > data_end)
            break;

        struct geneve_opt *opt = (void *)ptr;
        // High bit of type (bit 7 / 0x80) indicates Critical Option
        if (opt->type & 0x80)
            return XDP_DROP;

        int len = (opt->flags_length & 0x1F) * 4;
        ptr += sizeof(struct geneve_opt) + len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
