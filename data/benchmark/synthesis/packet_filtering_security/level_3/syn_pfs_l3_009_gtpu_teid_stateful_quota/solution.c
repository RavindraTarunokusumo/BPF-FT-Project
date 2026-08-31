#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MAX_BYTE_QUOTA 102400ULL // 100 KB quota per TEID

struct teid_quota_stat {
    __u64 bytes_consumed;
    __u64 pkts_consumed;
};

struct gtpuhdr {
    __u8 flags;
    __u8 msg_type;
    __be16 length;
    __be32 teid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // TEID
    __type(value, struct teid_quota_stat);
    __uint(max_entries, 1024);
} teid_quota_map SEC(".maps");

SEC("xdp")
int xdp_gtpu_quota_enforcer(struct xdp_md *ctx) {
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

    if (gtp->msg_type != 0xFF) // Only meter G-PDU user data
        return XDP_PASS;

    __u32 teid = bpf_ntohl(gtp->teid);
    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);

    struct teid_quota_stat *st = bpf_map_lookup_elem(&teid_quota_map, &teid);
    if (!st) {
        struct teid_quota_stat new_st = { .bytes_consumed = pkt_len, .pkts_consumed = 1 };
        bpf_map_update_elem(&teid_quota_map, &teid, &new_st, BPF_ANY);
        return XDP_PASS;
    }

    if (st->bytes_consumed + pkt_len > MAX_BYTE_QUOTA)
        return XDP_DROP;

    st->bytes_consumed += pkt_len;
    st->pkts_consumed += 1;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
