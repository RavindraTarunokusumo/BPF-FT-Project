#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct napt_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct napt_tuple);
    __type(value, struct napt_tuple);
    __uint(max_entries, 1024);
} napt_fwd_map SEC(".maps");

SEC("xdp")
int xdp_stateful_napt(struct xdp_md *ctx) {
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

    // Outbound: from 10.0.0.0/24 subnet -> SNAT
    if ((bpf_ntohl(ip->saddr) & 0xFFFFFF00) == 0x0A000000) {
        ip->saddr = bpf_htonl(0xC6336401); // 198.51.100.1
        tcp->source = bpf_htons(30000);
        ip->check = 0;

        __u16 *words = (void *)ip;
        __u32 csum = 0;
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if ((void *)(words + i + 1) > data_end)
                return XDP_PASS;
            csum += bpf_ntohs(words[i]);
        }
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = bpf_htons((~csum) & 0xFFFF);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
