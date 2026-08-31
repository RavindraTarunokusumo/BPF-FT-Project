#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct sctphdr {
    __be16 src_port;
    __be16 dst_port;
    __be32 vtag;
    __be32 checksum;
};

struct sctp_chunkhdr {
    __u8 chunk_type;
    __u8 chunk_flags;
    __be16 chunk_length;
};

SEC("xdp")
int xdp_sctp_abort_filter(struct xdp_md *ctx) {
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
    if (ip->protocol != 132) // IPPROTO_SCTP
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct sctphdr *sctp = (void *)ip + ip_len;
    if ((void *)(sctp + 1) > data_end)
        return XDP_PASS;

    struct sctp_chunkhdr *chunk = (void *)(sctp + 1);
    if ((void *)(chunk + 1) > data_end)
        return XDP_PASS;

    if (chunk->chunk_type == 6) // ABORT Chunk
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
