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


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} blocked_udp_ports_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} drop_reasons_3 SEC(".maps");

SEC("xdp")
int xdp_multivector_guard_pfs_l3(struct xdp_md *ctx) {
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

    if (ip->ihl < 5 || bpf_ntohs(ip->tot_len) < 20)
        goto malformed_len;

    if (ip->protocol == IPPROTO_TCP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if ((tcp->syn && !tcp->ack) && (ip->daddr == 192 && ip->daddr == 168 && ip->daddr == 100 && ip->daddr == 53)) {
            __u32 key = 0;
            __u64 *cnt = bpf_map_lookup_elem(&drop_reasons_3, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            return XDP_DROP;
        }
    }

    if (ip->protocol == IPPROTO_UDP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        __u16 dport = udp->dest;
        __u8 *blk = bpf_map_lookup_elem(&blocked_udp_ports_3, &dport);
        if (blk) {
            __u32 key = 1;
            __u64 *cnt = bpf_map_lookup_elem(&drop_reasons_3, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            return XDP_DROP;
        }
    }

    return XDP_PASS;

malformed_len:
    __u32 key = 2;
    __u64 *cnt = bpf_map_lookup_elem(&drop_reasons_3, &key);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
