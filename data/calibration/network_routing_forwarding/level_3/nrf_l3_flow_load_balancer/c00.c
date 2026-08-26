#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, unsigned char[6]);
} backend_macs SEC(".maps");

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 2);
} backend_devmap SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_flow_lb(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Check IPv4 header
    struct iphdr *ip = (struct iphdr *)(eth + sizeof(*eth));
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->version != 4)
        return XDP_PASS;

    // Check TCP/UDP
    __u8 proto = ip->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return XDP_PASS;

    // Parse L4 ports
    void *l4_start = (void *)ip + sizeof(*ip);
    if (l4_start > data_end)
        return XDP_PASS;

    __u16 sport = 0, dport = 0;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_start;
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
        sport = ntohs(tcp->source);
        dport = ntohs(tcp->dest);
    } else { // UDP
        struct udphdr *udp = l4_start;
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
        sport = ntohs(udp->source);
        dport = ntohs(udp->dest);
    }

    // Compute flow hash
    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u32 hash = (saddr ^ daddr ^ ((__u32)sport << 16 | dport) ^ proto) & 1;

    // Lookup backend MAC
    unsigned char mac[6];
    __u32 idx = hash;
    int ret = bpf_map_lookup_elem(&backend_macs, &idx, mac);
    if (ret != 0)
        return XDP_PASS;

    // Update Ethernet destination MAC
    eth->h_dest[0] = mac[0];
    eth->h_dest[1] = mac[1];
    eth->h_dest[2] = mac[2];
    eth->h_dest[3] = mac[3];
    eth->h_dest[4] = mac[4];
    eth->h_dest[5] = mac[5];

    // Redirect via devmap
    int redirect_ret = bpf_redirect_map(&backend_devmap, idx, 0);
    if (redirect_ret < 0)
        return XDP_PASS;
    return XDP_REDIRECT;
}
