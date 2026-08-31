#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

enum drop_reason {
    DROP_SYN_PRIV = 0,
    DROP_UDP_NTP = 1,
    DROP_MALFORMED = 2,
    DROP_MAX = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} drop_stats SEC(".maps");

static __always_inline void record_drop(__u32 reason) {
    if (reason >= 4)
        return;
    __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &reason);
    if (cnt)
        *cnt += 1;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end) {
        record_drop(DROP_MALFORMED);
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end) {
            record_drop(DROP_MALFORMED);
            return XDP_DROP;
        }
        __u16 dport = bpf_ntohs(tcp->dest);
        if (tcp->syn && !tcp->ack && dport >= 1 && dport <= 1023) {
            record_drop(DROP_SYN_PRIV);
            return XDP_DROP;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end) {
            record_drop(DROP_MALFORMED);
            return XDP_DROP;
        }
        if (udp->dest == bpf_htons(123)) {
            record_drop(DROP_UDP_NTP);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
