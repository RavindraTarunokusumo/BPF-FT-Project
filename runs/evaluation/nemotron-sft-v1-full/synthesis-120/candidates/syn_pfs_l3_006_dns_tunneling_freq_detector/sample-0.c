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

struct dns_client_stat {
    __u64 window_start_ns;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct dns_client_stat);
} dns_tunnel_map SEC(".maps");

SEC("xdp")
int xdp_filter_syn_pfs_l3_006_dns_tunneling_freq_detector(struct xdp_md *ctx) {
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

    __u8 *p = (void *)(udp + 1);
    if ((void *)p + 4 > data_end)
        return XDP_PASS;

    if (p[0] != 0x01 || p[1] != 0x00 || p[2] != 0x00 || p[3] != 0x00)
        return XDP_PASS;

    __be32 client_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();
    __u64 window_start = (now / 1000000000) * 1000000000;

    struct dns_client_stat *stat = bpf_map_lookup_elem(&dns_tunnel_map, &client_ip);
    if (stat) {
        if (now - stat->window_start_ns >= 1000000000) {
            stat->window_start_ns = window_start;
            stat->total_bytes = 0;
        }
        if (stat->total_bytes > 500)
            return XDP_DROP;
        stat->total_bytes += (now - stat->window_start_ns);
    } else {
        struct dns_client_stat initial = {
            .window_start_ns = window_start,
            .total_bytes = 0,
        };
        bpf_map_update_elem(&dns_tunnel_map, &client_ip, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
