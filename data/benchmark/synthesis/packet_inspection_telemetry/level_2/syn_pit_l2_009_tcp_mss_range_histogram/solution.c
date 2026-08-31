#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0: <1200, 1: 1200-1400, 2: 1401-1460, 3: >1460
} mss_histogram_map SEC(".maps");

SEC("xdp")
int xdp_tcp_mss_histogram(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!tcp->syn)
        return XDP_PASS;

    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len <= sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    __u8 *opt = (void *)(tcp + 1);
    __u8 *opt_end = (void *)tcp + tcp_hdr_len;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (opt + 1 > opt_end || opt + 1 > data_end)
            break;

        __u8 kind = *opt;
        if (kind == 0) break;
        if (kind == 1) { opt += 1; continue; }

        if (opt + 2 > opt_end || opt + 2 > data_end)
            break;
        __u8 len = *(opt + 1);
        if (len < 2) break;

        if (kind == 2 && len == 4) { // MSS
            if (opt + 4 > opt_end || opt + 4 > data_end)
                break;
            __u16 mss = ((__u16)*(opt + 2) << 8) | (__u16)*(opt + 3);
            __u32 key = 0;
            if (mss < 1200) key = 0;
            else if (mss <= 1400) key = 1;
            else if (mss <= 1460) key = 2;
            else key = 3;

            __u64 *cnt = bpf_map_lookup_elem(&mss_histogram_map, &key);
            if (cnt)
                *cnt += 1;
            break;
        }

        opt += len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
