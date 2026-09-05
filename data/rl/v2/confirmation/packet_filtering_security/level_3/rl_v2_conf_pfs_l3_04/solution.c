#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} syn_subnet_map SEC(".maps");

SEC("xdp")
int xdp_filter_syn_subnet(struct xdp_md *ctx) {
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

    if (tcp->syn) {
        __u32 subnet = ip->saddr & bpf_htonl(0xFFFFFF00);
        __u32 *count = bpf_map_lookup_elem(&syn_subnet_map, &subnet);
        if (count) {
            __sync_fetch_and_add(count, 1);
            if (*count > 200)
                return XDP_DROP;
        } else {
            __u32 init_c = 1;
            bpf_map_update_elem(&syn_subnet_map, &subnet, &init_c, BPF_NOEXIST);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
