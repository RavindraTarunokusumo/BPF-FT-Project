#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_wg_peer_router(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(51820) && udp->source != bpf_htons(51820))
        return XDP_PASS;

    __u8 *wg = (void *)(udp + 1);
    if (wg + 8 > data_end)
        return XDP_PASS;

    __u32 msg_type = *(__u32 *)wg;
    if ((msg_type & 0xFF) != 4)
        return XDP_PASS;

    __u32 receiver_idx = *(__u32 *)(wg + 4);
    if (receiver_idx == bpf_htonl(0x11111111))
        return bpf_redirect(25, 0);
    if (receiver_idx == bpf_htonl(0x22222222))
        return bpf_redirect(26, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
