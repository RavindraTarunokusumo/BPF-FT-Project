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
} quarantine_map SEC(".maps");

SEC("xdp")
int xdp_quarantine_syn_pfs_l3_010_dynamic_ip_reputation_quarantine(struct xdp_md *ctx) {
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

    __be32 src_ip = ip->saddr;
    struct ip_reputation *rep = bpf_map_lookup_elem(&quarantine_map, &src_ip);
    if (rep) {
        if (rep->quarantine_until_ns > bpf_ktime_get_ns())
            return XDP_DROP;
        else
            bpf_map_delete_elem(&quarantine_map, &src_ip);
    }

    if (ip->protocol == IPPROTO_TCP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr))
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if (tcp->syn && tcp->fin) {
            __u32 new_count = __sync_fetch_and_add(&rep->bad_event_count, 1);
            if (new_count + 1 >= 3) {
                rep->quarantine_until_ns = bpf_ktime_get_ns() + 60000000000ULL;
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
