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
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} redirect_map SEC(".maps");

SEC("xdp")
int xdp_route_syn_nrf_l2_002_ipv6_lpm_trie_router(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 *d = (void *)&ip->daddr;
    if (d[0] == 0x20 && d[1] == 0x01 && d[2] == 0xdb && d[3] == 0x8 &&
        d[4] == 0x01 && d[5] == 0x00 && d[6] == 0x00 && d[7] == 0x00 &&
        d[8] == 0x00 && d[9] == 0x00 && d[10] == 0x00 && d[11] == 0x00 &&
        d[12] == 0x00 && d[13] == 0x00 && d[14] == 0x00 && d[15] == 0x00)
        return bpf_redirect(10, 0);

    if (d[0] == 0x20 && d[1] == 0x01 && d[2] == 0xdb && d[3] == 0x8 &&
        d[4] == 0x02 && d[5] == 0x00 && d[6] == 0x00 && d[7] == 0x00 &&
        d[8] == 0x00 && d[9] == 0x00 && d[10] == 0x00 && d[11] == 0x00 &&
        d[12] == 0x00 && d[13] == 0x00 && d[14] == 0x00 && d[15] == 0x00)
        return bpf_redirect(11, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
