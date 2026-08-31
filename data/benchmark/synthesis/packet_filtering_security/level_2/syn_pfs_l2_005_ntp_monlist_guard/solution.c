#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct ntphdr {
    __u8 li_vn_mode;
    __u8 stratum;
    __u8 poll;
    __u8 precision;
    __u32 root_delay;
    __u32 root_dispersion;
    __u32 ref_id;
    __u64 ref_ts;
    __u64 orig_ts;
    __u64 recv_ts;
    __u64 trans_ts;
};

SEC("xdp")
int xdp_ntp_guard(struct xdp_md *ctx) {
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

    // Check NTP port 123 (either source or destination)
    if (udp->dest != bpf_htons(123) && udp->source != bpf_htons(123))
        return XDP_PASS;

    struct ntphdr *ntp = (void *)(udp + 1);
    if ((void *)(ntp + 1) > data_end)
        return XDP_PASS;

    // Mode is bottom 3 bits: (li_vn_mode & 0x07)
    __u8 mode = ntp->li_vn_mode & 0x07;
    if (mode == 6 || mode == 7) // Mode 6 (Control) or Mode 7 (Private/Monlist)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
