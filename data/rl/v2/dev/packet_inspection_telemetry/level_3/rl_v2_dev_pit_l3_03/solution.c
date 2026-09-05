#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} win_dist_03 SEC(".maps");

SEC("xdp")
int xdp_win_3(struct xdp_md *ctx) {
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

    __u16 win = bpf_ntohs(tcp->window);
    __u32 bin = 0;
    if (win < 4096)
        bin = 0;
    else if (win < 16384)
        bin = 1;
    else if (win < 65535)
        bin = 2;
    else
        bin = 3;

    __u64 *val = bpf_map_lookup_elem(&win_dist_03, &bin);
    if (val)
        __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
