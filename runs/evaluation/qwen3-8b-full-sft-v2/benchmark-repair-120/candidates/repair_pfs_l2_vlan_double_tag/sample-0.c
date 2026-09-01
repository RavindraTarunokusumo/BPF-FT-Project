#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *nh = (void *)(eth + 1);

    if (eth_proto == ETH_P_8021Q || eth_proto == 0x88A8) {
        struct vlan_hdr *vlh = nh;
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;
        eth_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
        nh = (void *)(vlh + 1);
    }

    if (eth_proto == ETH_P_8021Q || eth_proto == 0x88A8) {
        struct vlan_hdr *vlh = nh;
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;
        eth_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
        nh = (void *)(vlh + 1);
    }

    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = nh;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(23))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
