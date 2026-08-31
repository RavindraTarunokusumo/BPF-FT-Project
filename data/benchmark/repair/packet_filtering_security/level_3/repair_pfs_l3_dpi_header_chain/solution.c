#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest != bpf_htons(80))
        return XDP_PASS;

    __u32 tcp_len = (__u32)tcp->doff * 4;
    if (tcp_len < sizeof(struct tcphdr) || (void *)tcp + tcp_len > data_end)
        return XDP_PASS;

    char *payload = (void *)tcp + tcp_len;
    if ((void *)(payload + 10) > data_end)
        return XDP_PASS;

    if (payload[4] == '/' && payload[5] == 'a' && payload[6] == 'd' && payload[7] == 'm' && payload[8] == 'i' && payload[9] == 'n')
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
