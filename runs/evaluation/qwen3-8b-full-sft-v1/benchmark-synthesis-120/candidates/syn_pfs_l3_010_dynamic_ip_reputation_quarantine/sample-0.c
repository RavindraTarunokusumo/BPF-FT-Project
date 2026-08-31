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


struct ip_reputation {
    __u32 bad_event_count;
    __u64 quarantine_until_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct ip_reputation);
} quarantine_map_10 SEC(".maps");

SEC("xdp")
int xdp_quarantine_pfs_l3_010(struct xdp_md *ctx) {
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

    __u8 *p = (void *)&ip->saddr;
    if (p[0] == 192 && p[1] == 168 && p[2] == 10 && p[3] == 50)
        return XDP_DROP;

    struct ip_reputation *r = bpf_map_lookup_elem(&quarantine_map_10, &ip->saddr);
    if (r) {
        __u64 now = bpf_ktime_get_ns();
        if (now < r->quarantine_until_ns)
            return XDP_DROP;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip + 1);
            if ((void *)(tcp + 1) <= data_end) {
                __u16 flags = tcp->syn + tcp->fin;
                if (flags == 3 || flags == 0) {
                    __sync_fetch_and_add(&r->bad_event_count, 1);
                    if (r->bad_event_count >= 3) {
                        r->quarantine_until_ns = bpf_ktime_get_ns() + 60 * 1e9;
                        return XDP_DROP;
                    }
                }
            }
        }
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            __u16 flags = tcp->syn + tcp->fin;
            if (flags == 3 || flags == 0) {
                __u32 cnt = 1;
                __builtin_memcpy(&cnt, r ? &r->bad_event_count : NULL, sizeof(cnt));
                if (cnt >= 3) {
                    struct ip_reputation new = {
                        .bad_event_count = 3,
                        .quarantine_until_ns = bpf_ktime_get_ns() + 60 * 1e9,
                    };
                    bpf_map_update_elem(&quarantine_map_10, &ip->saddr, &new, BPF_ANY);
                    return XDP_DROP;
                }
                __sync_fetch_and_add(&cnt, 1);
                bpf_map_update_elem(&quarantine_map_10, &ip->saddr, &cnt, BPF_ANY);
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
