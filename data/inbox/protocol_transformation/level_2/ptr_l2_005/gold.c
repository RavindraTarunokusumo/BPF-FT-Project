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
} snat_table_5 SEC(".maps");

SEC("xdp")
int xdp_transform_ptr_l2_005(struct xdp_md *ctx) {
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

    __u32 src_ip = ip->saddr;
    __u32 *new_ip = bpf_map_lookup_elem(&snat_table_5, &src_ip);
    if (new_ip) {
        __u32 old_saddr = ip->saddr;
        ip->saddr = *new_ip;
        // Adjust IP checksum
        __u32 csum = (__u32)ip->check + (old_saddr & 0xFFFF) + (old_saddr >> 16)
                     - ((*new_ip) & 0xFFFF) - ((*new_ip) >> 16);
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = (__u16)csum;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
