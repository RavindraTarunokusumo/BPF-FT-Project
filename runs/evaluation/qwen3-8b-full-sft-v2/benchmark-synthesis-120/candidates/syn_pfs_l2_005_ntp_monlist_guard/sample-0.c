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

struct ntphdr {
    __u8  li_vn_mode;
    __u8  stratum;
    __u16 poll;
    __u16 precision;
    __u32 root_delay;
    __u32 root_disp;
    __u32 ref_id;
    __u64 ref_t;
    __u64 recv_t;
    __u64 trans_t;
    __u64 key_id;
};

SEC("xdp")
int xdp_filter_syn_pfs_l2_005_ntp_monlist_guard(struct xdp_md *ctx) {
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(123) || udp->source == bpf_htons(123)) {
        struct ntphdr *ntp = (void *)(udp + 1);
        if ((void *)(ntp + 1) > data_end)
            return XDP_PASS;

        __u8 mode = ntp->li_vn_mode & 0x07;
        if (mode == 6 || mode == 7)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
