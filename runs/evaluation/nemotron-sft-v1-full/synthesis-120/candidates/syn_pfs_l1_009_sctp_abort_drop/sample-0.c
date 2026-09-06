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

struct sctphdr {
    __u16 source;
    __u16 dest;
    __u32 verification_tag;
    __u32 checksum;
};

struct sctp_chunkhdr {
    __u8 chunk_type;
    __u8 flags;
    __be16 length;
};

SEC("xdp")
int xdp_filter_syn_pfs_l1_009_sctp_abort_drop(struct xdp_md *ctx) {
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

    if (ip->protocol != 132)
        return XDP_PASS;

    if (ip->ihl < 5)
        return XDP_PASS;

    struct sctphdr *sctp = (void *)ip + ip->ihl * 4;
    if ((void *)(sctp + 1) > data_end)
        return XDP_PASS;

    struct sctp_chunkhdr *chunk = (void *)(sctp + 1);
    if ((void *)(chunk + 1) > data_end)
        return XDP_PASS;

    if (chunk->chunk_type == 6)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
