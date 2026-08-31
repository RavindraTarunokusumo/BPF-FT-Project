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
int xdp_transform_syn_ptr_l3_007_geneve_metadata_insertion(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_end = (unsigned long)ip + ip_hdr_len;
    if (ip_hdr_end <= (unsigned long)ip + sizeof(struct iphdr))
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    struct genevehdr *gen = (void *)(udp + 1);
    if ((void *)(gen + 1) > data_end)
        return XDP_PASS;

    if (gen->opt_len != 0)
        return XDP_PASS;

    __u64 adj = -8;
    if ((void *)gen + adj < (void *)eth)
        return XDP_PASS;

    gen = (__u8 *)gen + adj;
    if ((void *)(gen + 1) > data_end)
        return XDP_PASS;

    gen->class = bpf_htons(0x0100);
    gen->type = 1;
    gen->vlen = 2;
    __u32 *d = (__u8 *)gen + sizeof(struct geneve_tlv_hdr);
    *d = 0xDEADBEEF;

    __u32 *opt_len = &gen->opt_len;
    __u32 new_opt_len = 2;
    __sync_fetch_and_add(opt_len, new_opt_len);

    __u16 *udpl = &udp->len;
    __sync_fetch_and_add(udpl, 8);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
