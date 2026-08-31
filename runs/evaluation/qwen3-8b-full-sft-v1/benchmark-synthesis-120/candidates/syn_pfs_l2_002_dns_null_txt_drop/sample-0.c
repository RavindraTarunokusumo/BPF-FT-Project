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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    if (udp->len < sizeof(struct udphdr))
        return XDP_PASS;

    unsigned char *dns = (void *)udp + udp_hdr_len;
    if ((void *)dns + sizeof(struct dns_hdr) > data_end)
        return XDP_PASS;

    struct dns_hdr *d = (void *)dns;
    if ((void *)(d + 1) > data_end)
        return XDP_PASS;

    if (d->qr != 0)
        return XDP_PASS;

    if (d->qdcount < 1)
        return XDP_PASS;

    unsigned char *qname = (void *)&d->qdcount + sizeof(u16);
    if ((void *)qname > data_end)
        return XDP_PASS;

    while (qname < data_end && *qname != 0)
        qname++;

    if ((void *)qname >= data_end)
        return XDP_PASS;

    if ((void *)qname - (void *)d < sizeof(struct dns_hdr))
        return XDP_PASS;

    qname += 1;
    if ((void *)qname > data_end)
        return XDP_PASS;

    if ((void *)qname + sizeof(u16) > data_end)
        return XDP_PASS;

    u16 qtype = *(u16 *)qname;
    if (qtype == 10 || qtype == 16)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
