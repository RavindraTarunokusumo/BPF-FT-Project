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
    __u8 flags_length;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=Linux(0x0100), 1=OVS(0x0101), 2=AWS(0x0102), 3=Other
} geneve_class_map SEC(".maps");

SEC("xdp")
int xdp_geneve_class_histogram(struct xdp_md *ctx) {
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

    int opt_bytes = gen->opt_len * 4;
    if (opt_bytes == 0)
        return XDP_PASS;

    void *opts_start = (void *)(gen + 1);
    void *opts_end = opts_start + opt_bytes;
    if (opts_end > data_end)
        return XDP_PASS;

    __u8 *ptr = opts_start;

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (ptr + sizeof(struct geneve_opt) > opts_end || ptr + sizeof(struct geneve_opt) > data_end)
            break;

        struct geneve_opt *opt = (void *)ptr;
        __u16 opt_class = bpf_ntohs(opt->opt_class);

        __u32 key = 3;
        if (opt_class == 0x0100) key = 0;
        else if (opt_class == 0x0101) key = 1;
        else if (opt_class == 0x0102) key = 2;

        __u64 *cnt = bpf_map_lookup_elem(&geneve_class_map, &key);
        if (cnt)
            *cnt += 1;

        int len = (opt->flags_length & 0x1F) * 4;
        ptr += sizeof(struct geneve_opt) + len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
