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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} dns_qtype_dist_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l2_003_dns_qtype_distribution(struct xdp_md *ctx) {
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

    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    if (udp->len < sizeof(*udp))
        return XDP_PASS;

    unsigned char *dns = (void *)(udp + 1);
    if ((void *)(dns + 60) > data_end)
        return XDP_PASS;

    if (dns[2] != 0 || dns[3] != 0)
        return XDP_PASS;

    __u16 qtype = bpf_ntohs(*(__u16 *)(dns + 12));
    __u32 key = 0;
    if (qtype == bpf_htons(1))
        key = 0;
    else if (qtype == bpf_htons(28))
        key = 1;
    else if (qtype == bpf_htons(5))
        key = 2;
    else if (qtype == bpf_htons(15))
        key = 3;
    else if (qtype == bpf_htons(16))
        key = 4;
    else
        key = 5;

    __u64 *cnt = bpf_map_lookup_elem(&dns_qtype_dist_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
