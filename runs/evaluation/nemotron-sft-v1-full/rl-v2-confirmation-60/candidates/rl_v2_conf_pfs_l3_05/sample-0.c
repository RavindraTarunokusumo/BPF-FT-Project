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


SEC("xdp")
int xdp_rl_v2_conf_pfs_l3_05(struct xdp_md *ctx) {
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

    __u8 *mac = bpf_map_lookup_elem(&mac_ip_auth_map, &ip->saddr);
    if (mac) {
        if (eth->h_source[0] != mac[0] ||
            eth->h_source[1] != mac[1] ||
            eth->h_source[2] != mac[2] ||
            eth->h_source[3] != mac[3] ||
            eth->h_source[4] != mac[4] ||
            eth->h_source[5] != mac[5])
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
