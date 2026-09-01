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
} blocked_udp_ports_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} drop_reasons_1 SEC(".maps");

SEC("xdp")
int xdp_pfs_l3_multivector_guard(struct xdp_md *ctx) {
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

    __u32 len = ip->tot_len;
    if (len < 20 || bpf_ntohs(len) < 20)
        return XDP_DROP;

    if (ip->ihl < 5)
        return XDP_DROP;

    if (ip->protocol == IPPROTO_TCP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;

        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        if ((tcp->syn && !tcp->ack) && (tcp->dest >= 1 && tcp->dest <= 1023)) {
            __u32 key = 0;
            bpf_map_update_elem(&drop_reasons_1, &key, (void *)(__u64)atomic64_add(1, (atomic64_t *)bpf_map_lookup_elem(&drop_reasons_1, &key)));
            return XDP_DROP;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;

        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        __u16 dport = udp->dest;
        __u8 *val = bpf_map_lookup_elem(&blocked_udp_ports_1, &dport);
        if (val) {
            __u32 key = 1;
            bpf_map_update_elem(&drop_reasons_1, &key, (void *)(__u64)atomic64_add(1, (atomic64_t *)bpf_map_lookup_elem(&drop_reasons_1, &key)));
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
