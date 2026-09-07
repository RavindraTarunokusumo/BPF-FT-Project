#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
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

    __be32 old_src = ip->saddr;
    __be32 new_src = bpf_htonl(0xC6336401);
    ip->saddr = new_src;

    /* Recalculate IPv4 header checksum */
    __u32 csum = bpf_ntohs(ip->check);
    csum += bpf_htonl(0xC6336401);   /* add new source address */
    csum += bpf_htonl(~0xC6336401);  /* add one's complement of new source */
    ip->check = bpf_htons(~csum);    /* store one's complement of sum */

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
