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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} tcp_flags_4 SEC(".maps");

SEC("xdp")
int xdp_telemetry_rl_v2_conf_pit_l1_04(struct xdp_md *ctx) {
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

    unsigned int key = 0;
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u8 syn = 1 << 1; // bit 1
    __u8 ack = 1 << 4; // bit 4
    __u8 fin = 1 << 0; // bit 0
    __u8 rst = 1 << 2; // bit 2
    __u8 psh = 1 << 3; // bit 3

    if (tcp->syn)
        key = 0;
    else if (tcp->ack)
        key = 1;
    else if (tcp->fin)
        key = 2;
    else if (tcp->rst)
        key = 3;
    else if (tcp->psh)
        key = 4;

    __u64 *cnt = bpf_map_lookup_elem(&tcp_flags_4, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
