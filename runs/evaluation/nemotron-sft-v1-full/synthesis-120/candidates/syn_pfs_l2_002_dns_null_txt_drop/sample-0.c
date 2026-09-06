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

SEC("xdp")
int xdp_filter_syn_pfs_l2_002_dns_null_txt_drop(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    if (ip->dport != bpf_htons(53))
        return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    struct dns_hdr {
        __u16 id;
        __u16 flags;
        __u16 qdcount;
        __u16 ancount;
        __u16 nscount;
        __u16 arcount;
    } *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    if ((dns->flags & bpf_htons(0x8000)) != 0)
        return XDP_PASS;

    if (dns->qdcount == 0)
        return XDP_PASS;

    unsigned char *qname = (void *)(dns + 1);
    if ((void *)(qname + 1) > data_end)
        return XDP_PASS;

    while (*qname != 0) {
        if ((void *)(qname + 1 + *qname) > data_end)
            return XDP_PASS;
        qname += 1 + *qname;
    }

    if ((void *)(qname + 2) > data_end)
        return XDP_PASS;

    __u16 qtype = bpf_ntohs(*(__u16 *)qname);
    if (qtype == 10 || qtype == 16)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
