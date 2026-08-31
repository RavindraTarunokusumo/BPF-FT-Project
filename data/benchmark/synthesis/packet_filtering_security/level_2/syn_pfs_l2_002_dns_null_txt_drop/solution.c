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

SEC("xdp")
int xdp_dns_null_txt_filter(struct xdp_md *ctx) {
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
    // Bit 15 indicates QR (0 = Query, 1 = Response)
    if (flags & 0x8000)
        return XDP_PASS; // Only filter Queries

    if (bpf_ntohs(dns->qdcount) < 1)
        return XDP_PASS;

    __u8 *ptr = (void *)(dns + 1);

    // Skip QNAME labels (bounded loop)
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
            return XDP_PASS; // Pointer compression not allowed in standard query QNAME
        ptr += 1 + len;
    }

    // Now ptr points to QTYPE (2 bytes) + QCLASS (2 bytes)
    if (ptr + 4 > data_end)
        return XDP_PASS;

    __u16 qtype = ((__u16)*ptr << 8) | (__u16)*(ptr + 1);
    if (qtype == 10 || qtype == 16) // 10 = NULL, 16 = TXT
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
