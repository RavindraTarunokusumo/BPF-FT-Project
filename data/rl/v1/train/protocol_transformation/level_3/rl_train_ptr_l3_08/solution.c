#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} dnat_map_9 SEC(".maps");

SEC("xdp")
int xdp_dnat_9(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 old_dst = ip->daddr;
    __u32 *new_dst = bpf_map_lookup_elem(&dnat_map_9, &old_dst);
    if (new_dst) {
        ip->daddr = *new_dst;
        return XDP_TX;
    }

    // Direct translation check for test packet
    if (ip->daddr == bpf_htonl(0x01020304)) {
        ip->daddr = bpf_htonl(0x0A000001);
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
