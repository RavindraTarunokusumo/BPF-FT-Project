#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct gtpuhdr {
    __u8 flags;
    __u8 msg_type;
    __be16 length;
    __be32 teid;
};

SEC("xdp")
int xdp_gtpu_upf_remap(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    struct gtpuhdr *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > data_end)
        return XDP_PASS;

    if (gtp->teid == bpf_htonl(0x1000)) {
        gtp->teid = bpf_htonl(0x2000);
        ip->daddr = bpf_htonl(0xC6336401);
        ip->check = 0;

        __u16 *words = (void *)ip;
        __u32 csum = 0;
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if ((void *)(words + i + 1) > data_end)
                return XDP_PASS;
            csum += bpf_ntohs(words[i]);
        }
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = bpf_htons((~csum) & 0xFFFF);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
