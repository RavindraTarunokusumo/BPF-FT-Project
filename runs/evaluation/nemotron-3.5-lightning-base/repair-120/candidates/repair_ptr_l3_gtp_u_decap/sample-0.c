#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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
    if (ip->protocol != IPPROTO_UDP) // IPPROTO_UDP now declared via <linux/in.h>
        return XDP_PASS;

    /* Verify UDP payload exists and contains GTP-U port 2152 */
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->source != bpf_htons(2152) && udp->dest != bpf_htons(2152))
        return XDP_PASS;

    /* Strip 36-byte outer header: outer IPv4 (20) + UDP (8) + GTP-U (8) */
    int ret = bpf_xdp_adjust_head(ctx, 36);
    if (ret)
        return XDP_ABORTED;

    /* Re-validate adjusted packet bounds */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
