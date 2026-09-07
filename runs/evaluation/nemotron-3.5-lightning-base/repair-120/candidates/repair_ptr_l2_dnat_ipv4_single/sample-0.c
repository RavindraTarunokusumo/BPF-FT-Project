#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htonl(0xCB007109);
    ip->daddr = new_dst;

    /* Recalculate IPv4 header checksum */
    __u32 csum = bpf_ntohs(ip->check);
    csum = csum_unfold(csum); /* fold high 16 bits into low 16 */
    csum += (__u16)(~(__be16)old_dst;   /* add old destination (one's complement) */
    csum += (__u16)(~(__be16)new_dst;   /* add new destination (one's complement) */
    csum = csum_fold(csum);   /* fold back to 16 bits */
    ip->check = csum;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
