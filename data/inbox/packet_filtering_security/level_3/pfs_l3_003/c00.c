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


struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_key);
    __type(value, __u64);
} conn_track_3 SEC(".maps");

SEC("xdp")
int xdp_track_pfs_l3_003(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Missing unaligned memory pad in key structure and missing ip_hdr_len boundary check
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct flow_key key;
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.src_port = tcp->source;
    key.dst_port = tcp->dest;
    key.proto = ip->protocol;

    __u64 *val = bpf_map_lookup_elem(&conn_track_3, &key);
    if (!val)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
