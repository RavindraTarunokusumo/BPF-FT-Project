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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} ip_denylist_43 SEC(".maps");

SEC("xdp")
int xdp_denylist_pfs_l2_043(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Dereferencing map lookup pointer without checking if it is NULL
    __u32 src_ip = ip->saddr;
    __u32 *val = bpf_map_lookup_elem(&ip_denylist_43, &src_ip);
    if (*val == 1)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
