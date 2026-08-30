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
int xdp_filter_pfs_l2_source_subnet_exception(struct xdp_md *ctx) {
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

    __u8 *s = (void *)&ip->saddr;
    if (s[0] != 0xC6 || s[1] != 0x33 || s[2] != 0x64 || s[3] != 0x00)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_UDP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if (udp->dest == bpf_htons(53))
            return XDP_PASS;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
<|im_end|>
