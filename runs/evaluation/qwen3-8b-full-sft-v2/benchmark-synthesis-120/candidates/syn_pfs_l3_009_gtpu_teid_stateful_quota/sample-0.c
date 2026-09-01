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

struct teid_quota_stat {
    __u64 bytes_consumed;
    __u64 pkts_consumed;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct teid_quota_stat);
} teid_quota_map SEC(".maps");

SEC("xdp")
int xdp_filter_syn_pfs_l3_009_gtpu_teid_stateful_quota(struct xdp_md *ctx) {
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

    __u32 teid = udp->daddr;

    struct teid_quota_stat *stat = bpf_map_lookup_elem(&teid_quota_map, &teid);
    if (stat) {
        __u64 new_bytes = stat->bytes_consumed + (ctx->data_end - (void *)(long)ctx->data);
        if (new_bytes > 102400)
            return XDP_DROP;
        stat->bytes_consumed = new_bytes;
        stat->pkts_consumed += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
