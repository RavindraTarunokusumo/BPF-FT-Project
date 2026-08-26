#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (struct vlan_hdr *)((void *)eth + sizeof(*eth));
        if ((void *)vlan + 4 > data_end)
            return XDP_PASS;

        __be16 inner_ethertype = vlan->h_vlan_encapsulated_proto;
        if (inner_ethertype != bpf_htons(ETH_P_IP))
            return XDP_PASS;

        struct iphdr *ip = (struct iphdr *)((void *)vlan + 4 + 14);
        if ((void *)ip > data_end)
            return XDP_PASS;

        u32 ip_len = ip->ihl * 4;
        if ((void *)ip + ip_len > data_end)
            return XDP_PASS;

        if (ip->protocol != IPPROTO_TCP)
            return XDP_PASS;

        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip_len);
        if ((void *)tcp > data_end)
            return XDP_PASS;

        u32 tcp_len = tcp->doff * 4;
        if ((void *)tcp + tcp_len > data_end)
            return XDP_PASS;

        if (tcp->dest == bpf_htons(443))
            return XDP_DROP;

        return XDP_PASS;
    } else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
        if ((void *)ip > data_end)
            return XDP_PASS;

        u32 ip_len = ip->ihl * 4;
        if ((void *)ip + ip_len > data_end)
            return XDP_PASS;

        if (ip->protocol != IPPROTO_TCP)
            return XDP_PASS;

        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip_len);
        if ((void *)tcp > data_end)
            return XDP_PASS;

        u32 tcp_len = tcp->doff * 4;
        if ((void *)tcp + tcp_len > data_end)
            return XDP_PASS;

        if (tcp->dest == bpf_htons(443))
            return XDP_DROP;

        return XDP_PASS;
    }

    return XDP_PASS;
}
