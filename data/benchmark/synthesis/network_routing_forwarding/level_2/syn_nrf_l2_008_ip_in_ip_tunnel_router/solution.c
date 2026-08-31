#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_ipinip_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;
    if (outer_ip->protocol != 4)
        return XDP_PASS;

    int outer_len = outer_ip->ihl * 4;
    if (outer_len < sizeof(struct iphdr) || (void *)outer_ip + outer_len > data_end)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)outer_ip + outer_len;
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    __u32 inner_dst = bpf_ntohl(inner_ip->daddr);
    if ((inner_dst & 0xFFFF0000) == 0x0A010000) // 10.1.0.0/16
        return bpf_redirect(18, 0);
    if ((inner_dst & 0xFFFF0000) == 0x0A020000) // 10.2.0.0/16
        return bpf_redirect(19, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
