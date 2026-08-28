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
int xdp_denylist_pfs_l2_029(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // FAULT: Reading IP address without verifying (ip + 1) bounds against data_end
    struct iphdr *ip = (void *)(eth + 1);
    __u8 *s = (void *)&ip->saddr;
    if (s[0] == 192 && s[1] == 168 && s[2] == 29 && s[3] == 50)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
