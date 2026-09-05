#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

SEC("xdp")
int xdp_decap_ipip_7(struct xdp_md *ctx) {
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

    if (outer_ip->protocol == 4) {
        int outer_len = outer_ip->ihl * 4;
        if (outer_len < sizeof(struct iphdr) || (void *)outer_ip + outer_len > data_end)
            return XDP_PASS;

        struct ethhdr eth_backup;
        __builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));

        if (bpf_xdp_adjust_head(ctx, outer_len))
            return XDP_DROP;

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_DROP;

        __builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
