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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} redirect_map SEC(".maps");

SEC("xdp")
int xdp_route_syn_nrf_l3_005_evpn_distributed_gateway(struct xdp_md *ctx) {
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
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)(udp + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_dest.addr[0] != 0x00 ||
        inner_eth->h_dest.addr[1] != 0x00 ||
        inner_eth->h_dest.addr[2] != 0x5e ||
        inner_eth->h_dest.addr[3] != 0x00 ||
        inner_eth->h_dest.addr[4] != 0x01 ||
        inner_eth->h_dest.addr[5] != 0x01)
        return XDP_PASS;

    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    __u32 key = (inner_ip->daddr & 0xFFFFFFF0) == bpf_htons(10 * 256 * 256 + 1 * 256 + 0) ? 10 : 20;
    __u32 *val = bpf_map_lookup_elem(&redirect_map, &key);
    if (val)
        return bpf_redirect(*val, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
