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


struct napt_key {
    __u32 priv_ip;
    __u16 priv_port;
};

struct napt_val {
    __u32 pub_ip;
    __u16 pub_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct napt_key);
    __type(value, struct napt_val);
} napt_table_31 SEC(".maps");

SEC("xdp")
int xdp_transform_ptr_l3_031(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Unchecked map pointer and unaligned key structure
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct napt_key key;
    key.priv_ip = ip->saddr;
    key.priv_port = tcp->source;

    struct napt_val *val = bpf_map_lookup_elem(&napt_table_31, &key);
    ip->saddr = val->pub_ip;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
