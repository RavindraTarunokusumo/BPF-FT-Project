#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

struct bpf_map_def SEC("maps") proto_redirect_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 2,
};

SEC("xdp")
int xdp_redirect_program(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if ((unsigned long)(data_end - data) < (unsigned long)sizeof(struct ethhdr))
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Check IP header bounds
    void *ip_start = data + sizeof(struct ethhdr);
    if ((unsigned long)(data_end - ip_start) < (unsigned long)sizeof(struct iphdr))
        return XDP_PASS;

    struct iphdr *ip = ip_start;
    if (ip->ihl < 5 || ip_start + (ip->ihl * 4) > data_end)
        return XDP_PASS;

    int protocol = ip->protocol;
    if (protocol == IPPROTO_TCP) {
        __u32 key = 0;
        __u32 *val = bpf_map_lookup_elem(&proto_redirect_map, &key);
        if (val && *val != 0)
            return bpf_redirect(*val, 0);
    } else if (protocol == IPPROTO_UDP) {
        __u32 key = 1;
        __u32 *val = bpf_map_lookup_elem(&proto_redirect_map, &key);
        if (val && *val != 0)
            return bpf_redirect(*val, 0);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
