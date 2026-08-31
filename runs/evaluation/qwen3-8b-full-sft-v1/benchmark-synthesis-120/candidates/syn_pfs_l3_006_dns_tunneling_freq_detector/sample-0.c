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
    __type(key, __u32);
    __type(value, struct dns_client_stat);
} dns_tunnel_map_6 SEC(".maps");

SEC("xdp")
int xdp_dnstunneling_freq_detector(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    unsigned int ip_hdr_len2 = ip->ihl * 4;
    if (ip_hdr_len2 < sizeof(struct iphdr) || (void *)ip + ip_hdr_len2 > data_end)
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    unsigned int payload_len = udp->len - ip_hdr_len2;
    if (payload_len < sizeof(struct dns_hdr))
        return XDP_PASS;

    struct dns_hdr *dns = (void *)udp + udp_hdr_len;
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    if (dns->qr != 0)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    struct dns_client_stat *s = bpf_map_lookup_elem(&dns_tunnel_map_6, &src_ip);
    if (!s) {
        __u64 now = bpf_ktime_get_ns();
        s = bpf_map_lookup_elem(&dns_tunnel_map_6, &src_ip);
        if (!s) {
            struct dns_client_stat initial = {
                .window_start_ns = bpf_ktime_get_ns(),
                .total_bytes = (__u64)dns->payload_len,
            };
            int err = bpf_map_update_elem(&dns_tunnel_map_6, &src_ip, &initial, BPF_ANY);
            if (err < 0)
                return XDP_PASS;
            return XDP_PASS;
        }
    }

    __u64 now = bpf_ktime_get_ns();
    if (now - s->window_start_ns > 1000000000) {
        __u64 now = bpf_ktime_get_ns();
        s->window_start_ns = now;
        s->total_bytes = (__u64)dns->payload_len;
    } else {
        __u64 new_total = s->total_bytes + (__u64)dns->payload_len;
        if (new_total > 500) {
            return XDP_DROP;
        }
        s->total_bytes = new_total;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
