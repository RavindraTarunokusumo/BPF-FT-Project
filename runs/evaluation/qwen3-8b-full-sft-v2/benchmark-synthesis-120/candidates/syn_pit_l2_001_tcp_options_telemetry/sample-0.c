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
} tcp_options_freq_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l2_001_tcp_options_telemetry(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 *key = (void *)&tcp->doff * 4;
    if (tcp->doff < sizeof(struct tcphdr) / 4)
        return XDP_PASS;

    unsigned int options_len = (tcp->doff * 4) - sizeof(struct tcphdr);
    if (options_len < 0)
        return XDP_PASS;

    char *opt = (void *)tcp + sizeof(struct tcphdr);
    if ((void *)opt + options_len > data_end)
        return XDP_PASS;

    while (options_len > 0) {
        unsigned int opt_len = opt[1];
        if (opt_len < 2 || (void *)opt + opt_len > data_end)
            break;

        __u8 opt_kind = opt[0];
        if (opt_kind == 0)  // EOL
            break;

        if (opt_kind == 1)  // NOP
            goto next_opt;

        if (opt_kind == 2) {
            __sync_fetch_and_add(&tcp_options_freq_map.entries[0], 1);
        } else if (opt_kind == 3) {
            __sync_fetch_and_add(&tcp_options_freq_map.entries[1], 1);
        } else if (opt_kind == 4) {
            __sync_fetch_and_add(&tcp_options_freq_map.entries[2], 1);
        } else if (opt_kind == 8) {
            __sync_fetch_and_add(&tcp_options_freq_map.entries[3], 1);
        }

next_opt:
        opt += opt_len;
        options_len -= opt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
