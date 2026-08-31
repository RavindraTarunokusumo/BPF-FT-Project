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
int xdp_transform_syn_ptr_l2_009_gtpu_decap_to_inner_ipv4(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    unsigned int ip_hdr_end = (unsigned long)ip + ip_hdr_len;
    if (ip_hdr_end <= (unsigned long)ip + sizeof(struct iphdr))
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    __u64 new_data = (unsigned long)udp + sizeof(struct udphdr) + 8;
    if (new_data + 36 > (unsigned long)data_end)
        return XDP_PASS;

    int res = bpf_xdp_adjust_head(ctx, 36);
    if (res < 0)
        return XDP_PASS;

    struct ethhdr *new_eth = data;
    new_eth->h_proto = bpf_htons(ETH_P_IP);
    __builtin_memcpy(new_eth->h_dest, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(new_eth->h_source, eth->h_source, ETH_ALEN);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
