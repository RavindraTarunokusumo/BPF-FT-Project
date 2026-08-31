#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=Query, 1=Response
} dns_qr_map SEC(".maps");

SEC("xdp")
int xdp_dns_qr_split(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(53) && udp->source != bpf_htons(53))
        return XDP_PASS;

    void *dns_start = (void *)(udp + 1);
    if (dns_start + 4 > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(*(__be16 *)(dns_start + 2));
    __u32 key = (flags & 0x8000) ? 1 : 0; // Bit 15: 0=Query, 1=Response

    __u64 *cnt = bpf_map_lookup_elem(&dns_qr_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
