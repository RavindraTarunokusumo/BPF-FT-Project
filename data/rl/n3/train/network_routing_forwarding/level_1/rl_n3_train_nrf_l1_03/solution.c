#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_reflect_3(struct xdp_md *ctx) {
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

    unsigned char tmp_mac[ETH_ALEN];
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp_mac[i];
    }

    __u32 tmp_ip = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp_ip;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
