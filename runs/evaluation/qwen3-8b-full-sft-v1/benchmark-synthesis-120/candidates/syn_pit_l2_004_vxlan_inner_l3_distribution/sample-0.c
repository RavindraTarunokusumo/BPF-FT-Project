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
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} vxlan_inner_proto_map_4 SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l2_004_vxlan_inner_l3_distribution(struct xdp_md *ctx) {
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

    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    void *vxlan_hdr = (void *)udp + udp_hdr_len;
    if ((void *)(vxlan_hdr + 1) > data_end)
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)vxlan_hdr + sizeof(struct vxlanhdr);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 3; // Other

    if (inner_eth->h_proto == bpf_htons(ETH_P_IP))
        key = 0;
    else if (inner_eth->h_proto == bpf_htons(ETH_P_IPV6))
        key = 1;
    else if (inner_eth->h_proto == bpf_htons(ETH_P_ARP))
        key = 2;

    __u64 *cnt = bpf_map_lookup_elem(&vxlan_inner_proto_map_4, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
