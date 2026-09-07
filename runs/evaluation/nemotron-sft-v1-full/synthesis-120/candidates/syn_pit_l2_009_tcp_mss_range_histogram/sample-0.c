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
} mss_histogram_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l2_009_tcp_mss_range_histogram(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!tcp->syn)
        return XDP_PASS;

    unsigned int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    unsigned char *opts = (void *)(tcp + 1);
    while ((void *)opts + 3 <= data_end) {
        __u8 kind = opts[0];
        if (kind == 2) {
            if ((void *)opts + 4 <= data_end) {
                __u32 mss = bpf_ntohl(*(__u32 *)(opts + 2));
                __u32 key = 0;
                if (mss < 1200)
                    key = 0;
                else if (mss <= 1400)
                    key = 1;
                else if (mss <= 1460)
                    key = 2;
                else
                    key = 3;
                __u64 *cnt = bpf_map_lookup_elem(&mss_histogram_map, &key);
                if (cnt)
                    *cnt += 1;
            }
            break;
        }
        opts += opts[1];
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
