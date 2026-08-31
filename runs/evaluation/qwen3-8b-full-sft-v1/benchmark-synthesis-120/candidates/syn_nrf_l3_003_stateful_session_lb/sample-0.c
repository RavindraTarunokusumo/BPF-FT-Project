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
    __u16 src_port;
    __u16 pad;
    __u32 dst_ip;
    __u16 dst_port;
    __u16 pad2;
    __u8  proto;
    __u8  pad3[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow_key);
    __type(value, __u32);
} session_table_3 SEC(".maps");

SEC("xdp")
int xdp_sticky_session_lb(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.src_port = tcp->source;
    key.dst_ip = ip->daddr;
    key.dst_port = tcp->dest;
    key.proto = ip->protocol;

    __u64 hash = key.src_ip + key.src_port + key.dst_ip + key.dst_port + key.proto;
    __u32 ifindex = 50 + (hash % 2);

    if (tcp->syn && !tcp->ack) {
        __u32 *val = bpf_map_lookup_elem(&session_table_3, &key);
        if (val) {
            __u32 old_ifindex = *val;
            if (old_ifindex != ifindex) {
                bpf_map_update_elem(&session_table_3, &key, &ifindex, BPF_ANY);
            }
            return XDP_REDIRECT(old_ifindex);
        } else {
            bpf_map_update_elem(&session_table_3, &key, &ifindex, BPF_ANY);
            return XDP_REDIRECT(ifindex);
        }
    }

    __u32 *val = bpf_map_lookup_elem(&session_table_3, &key);
    if (val) {
        return XDP_REDIRECT(*val);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
