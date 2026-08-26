#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

SEC("maps")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, __u64);
} flow_counter_map SEC("maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct flow_key key = {};
    __u64 *count;

    // Check Ethernet header bounds
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IPv4 header
    ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + (ip->ihl * 4) > data_end)
        return XDP_PASS;

    // Check protocol
    switch (ip->protocol) {
        case IPPROTO_TCP:
            // Check TCP header bounds
            tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
            if ((void *)tcp > data_end || (void *)tcp + sizeof(*tcp) > data_end)
                return XDP_PASS;
            key.sport = bpf_ntohs(tcp->source);
            key.dport = bpf_ntohs(tcp->dest);
            key.proto = IPPROTO_TCP;
            break;
        case IPPROTO_UDP:
            // Check UDP header bounds
            udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
            if ((void *)udp > data_end || (void *)udp + sizeof(*udp) > data_end)
                return XDP_PASS;
            key.sport = bpf_ntohs(udp->source);
            key.dport = bpf_ntohs(udp->dest);
            key.proto = IPPROTO_UDP;
            break;
        default:
            return XDP_PASS;
    }

    // Set source and destination IPs
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;

    // Lookup in map
    count = bpf_map_lookup_elem(&flow_counter_map, &key);
    if (count) {
        *count += 1;
    } else {
        bpf_map_update_elem(&flow_counter_map, &key, &(__u64){1}, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
