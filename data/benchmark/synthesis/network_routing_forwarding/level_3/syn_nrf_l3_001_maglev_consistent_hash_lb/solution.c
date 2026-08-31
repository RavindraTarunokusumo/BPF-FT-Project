#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_maglev_lb(struct xdp_md *ctx) {
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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    __u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    } else {
        return XDP_PASS;
    }

    __u32 fhash = ip->saddr ^ ip->daddr ^ ((__u32)sport << 16 | dport) ^ ip->protocol;
    fhash = ((fhash >> 16) ^ fhash) * 0x45d9f3b;
    fhash = ((fhash >> 16) ^ fhash) * 0x45d9f3b;
    fhash = (fhash >> 16) ^ fhash;

    __u32 backend_id = fhash % 4;
    return bpf_redirect(100 + backend_id, 0);
}

char _license[] SEC("license") = "GPL";
