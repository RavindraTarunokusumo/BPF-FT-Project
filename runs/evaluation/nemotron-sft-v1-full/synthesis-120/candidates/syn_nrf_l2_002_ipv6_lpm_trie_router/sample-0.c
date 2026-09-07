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
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, __u8[BPF_MAX_RND_KEY]);
    __type(value, __u32);
} routing_table SEC(".maps");

SEC("xdp")
int xdp_route_syn_nrf_l2_002_ipv6_lpm_trie_router(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    __u8 *d = ip6->daddr.s6_addr;
    __u8 key[BPF_MAX_RND_KEY] = {0};

    // Prefix 2001:db8:1::/48
    if (d[0] == 0x20 && d[1] == 0x01 && d[2] == 0x0d && d[3] == 0xb8 &&
        d[4] == 0x01 && d[5] == 0x00 && d[6] == 0x00 && d[7] == 0x00)
        __builtin_memcpy(key, d, 16);

    __u32 *p = bpf_lpm_trie_lookup(&routing_table, key, sizeof(key));
    if (p) {
        int ifindex = *p;
        if (ifindex == 10)
            return bpf_redirect(10, 0);
        if (ifindex == 11)
            return bpf_redirect(11, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
