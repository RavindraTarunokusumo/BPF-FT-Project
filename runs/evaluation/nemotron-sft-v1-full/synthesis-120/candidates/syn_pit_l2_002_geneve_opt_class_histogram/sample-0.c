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
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} geneve_class_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l2_002_geneve_opt_class_histogram(struct xdp_md *ctx) {
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

    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    struct geneve_hdr {
        __u32 flags;
        __u32 len;
        __u32 otype;
        __u32 tunnel_id;
    } *geneve = (void *)(udp + 1);
    if ((void *)(geneve + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    if (geneve->otype == bpf_htons(0x0100))
        key = 0;
    else if (geneve->otype == bpf_htons(0x0101))
        key = 1;
    else if (geneve->otype == bpf_htons(0x0102))
        key = 2;
    else
        key = 3;

    __u64 *cnt = bpf_map_lookup_elem(&geneve_class_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
