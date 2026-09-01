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

struct gtpuhdr {
    __u8  flags;
    __u8  hdr_len;
    __u16 teid;
    __u32 sequence_number;
    __u32 payload_length;
};

SEC("xdp")
int xdp_route_syn_nrf_l2_003_gtpu_teid_devmap_router(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    unsigned char *payload = (void *)(udp + 1);
    if ((void *)payload + sizeof(struct gtpuhdr) > data_end)
        return XDP_PASS;

    struct gtpuhdr *gtp = (void *)payload;
    if (gtp->hdr_len < sizeof(struct gtpuhdr) || (void *)gtp + gtp->hdr_len > data_end)
        return XDP_PASS;

    if (gtp->teid == bpf_htons(0x00000100))
        return bpf_redirect(30, 0);

    if (gtp->teid == bpf_htons(0x00000200))
        return bpf_redirect(31, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";