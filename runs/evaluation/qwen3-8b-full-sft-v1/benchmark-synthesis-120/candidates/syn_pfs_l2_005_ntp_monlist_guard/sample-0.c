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
    __u8  li_vn_mode[4];
    __u8  stratum;
    __u8  poll;
    __u8  precision;
    __u32 root_delay;
    __u32 root_dispersion;
    __u32 ref_id;
    __u64 ref_time_sec;
    __u64 ref_time_usec;
    __u64 orig_time_sec;
    __u64 orig_time_usec;
    __u64 recv_time_sec;
    __u64 recv_time_usec;
    __u64 trans_time_sec;
    __u64 trans_time_usec;
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->source != bpf_htons(123) && udp->dest != bpf_htons(123))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    if (udp->len < sizeof(struct udphdr))
        return XDP_PASS;

    void *payload = (void *)(udp + 1);
    if ((void *)payload > data_end)
        return XDP_PASS;

    struct ntphdr *ntph = payload;
    if ((void *)(ntph + 1) > data_end)
        return XDP_PASS;

    __u8 mode = ntph->li_vn_mode[2] & 0x07;
    if (mode == 6 || mode == 7)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
