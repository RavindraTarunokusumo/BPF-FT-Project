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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} tcp_flag_counters SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header
    struct ethhdr *eth_hdr = data;
    if (data + sizeof(*eth_hdr) > data_end)
        return XDP_PASS;
    if (BPF_ntohs(eth_hdr->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip_hdr = data + sizeof(*eth_hdr);
    if ((void *)ip_hdr + (ip_hdr->ihl * 4) > data_end)
        return XDP_PASS;
    if (ip_hdr->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp_hdr = (struct tcphdr *)((void *)ip_hdr + (ip_hdr->ihl * 4));
    if ((void *)tcp_hdr + sizeof(*tcp_hdr) > data_end)
        return XDP_PASS;

    // Check TCP flags
    __u8 flags = tcp_hdr->th_flags;
    int slot = 0;
    if (flags & 0x02) { // SYN
        slot = 0;
    } else if (flags & 0x01) { // FIN
        slot = 1;
    } else if (flags & 0x04) { // RST
        slot = 2;
    } else {
        slot = 3;
    }

    // Update the map
    __u32 key = slot;
    __u64 *count;
    count = bpf_map_lookup_elem(&tcp_flag_counters, &key);
    if (count)
        *count += 1;

    return XDP_PASS;
}
