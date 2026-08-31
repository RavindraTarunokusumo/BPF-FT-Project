#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct dnshdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 6); // 0=A(1), 1=AAAA(28), 2=CNAME(5), 3=MX(15), 4=TXT(16), 5=OTHER
} dns_qtype_dist_map SEC(".maps");

SEC("xdp")
int xdp_dns_qtype_dist(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    struct dnshdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(dns->flags);
    if (flags & 0x8000) // Response -> skip
        return XDP_PASS;

    if (bpf_ntohs(dns->qdcount) < 1)
        return XDP_PASS;

    __u8 *ptr = (void *)(dns + 1);

    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (ptr + 1 > data_end)
            return XDP_PASS;
        __u8 len = *ptr;
        if (len == 0) {
            ptr += 1;
            break;
        }
        if (len > 63)
            return XDP_PASS;
        ptr += 1 + len;
    }

    if (ptr + 2 > data_end)
        return XDP_PASS;

    __u16 qtype = ((__u16)*ptr << 8) | (__u16)*(ptr + 1);
    __u32 key = 5; // OTHER
    if (qtype == 1) key = 0;       // A
    else if (qtype == 28) key = 1; // AAAA
    else if (qtype == 5) key = 2;  // CNAME
    else if (qtype == 15) key = 3; // MX
    else if (qtype == 16) key = 4; // TXT

    __u64 *cnt = bpf_map_lookup_elem(&dns_qtype_dist_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
