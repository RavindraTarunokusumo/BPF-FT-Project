#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IPv4 header
    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)ip + 1 > data_end)
        return XDP_PASS;

    // Check for malformed IPv4 length
    __u32 tot_len = bpf_ntohs(ip->tot_len);
    if (ip->ihl < 5 || tot_len < 20 || (data_end - data) < tot_len) {
        // Malformed length
        __u32 reason_index = 2;
        __u64 count = 1;
        bpf_map_update_elem(&drop_reasons, &reason_index, &count, BPF_ANY);
        return XDP_DROP;
    }

    // Check for privileged TCP SYN
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)tcp + 1 > data_end)
            return XDP_PASS;

        __u32 tcp_flags = bpf_ntohs(tcp->th_flags);
        if ((tcp_flags & 0x12) == 0x02) { // (flags & 0x12) == 0x02
            __u16 dport = bpf_ntohs(tcp->th_dport);
            if (dport >= 1 && dport <= 1023) {
                // Privileged TCP SYN
                __u32 reason_index = 0;
                __u64 count = 1;
                bpf_map_update_elem(&drop_reasons, &reason_index, &count, BPF_ANY);
                return XDP_DROP;
            }
        }
    }

    // Check for blocked UDP ports
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)udp + 1 > data_end)
            return XDP_PASS;

        __u16 dport = bpf_ntohs(udp->dest);
        __u8 flag;
        int res = bpf_map_lookup_elem(&blocked_udp_ports, &dport, &flag);
        if (res == 0) {
            // Blocked UDP port
            __u32 reason_index = 1;
            __u64 count = 1;
            bpf_map_update_elem(&drop_reasons, &reason_index, &count, BPF_ANY);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} blocked_udp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} drop_reasons SEC(".maps");
