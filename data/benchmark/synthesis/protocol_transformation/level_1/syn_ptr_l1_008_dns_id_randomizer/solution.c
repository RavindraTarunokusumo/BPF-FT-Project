#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_dns_id_randomizer(struct xdp_md *ctx) {
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

    __be16 *dns_id = (void *)(udp + 1);
    if ((void *)(dns_id + 1) > data_end)
        return XDP_PASS;

    __be16 old_id = *dns_id;
    __be16 new_id = old_id ^ bpf_htons(0xA55A);
    *dns_id = new_id;

    if (udp->check != 0) {
        __u32 csum = (~bpf_ntohs(udp->check)) & 0xFFFF;
        csum += (~bpf_ntohs(old_id)) & 0xFFFF;
        csum += bpf_ntohs(new_id);
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        csum = (~csum) & 0xFFFF;
        if (csum == 0)
            csum = 0xFFFF;
        udp->check = bpf_htons((__u16)csum);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
