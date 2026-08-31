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


struct napt_tuple {
    __u32 priv_src_ip;
    __u16 priv_src_port;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct napt_tuple);
    __type(value, __u64);
} napt_fwd_44 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct napt_tuple);
    __type(value, __u64);
} napt_rev_44 SEC(".maps");

SEC("xdp")
int xdp_transform_syn_ptr_l3_004_stateful_napt44(struct xdp_md *ctx) {
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

    struct napt_tuple key = {};
    __u8 *d = (void *)&key;
    #pragma unroll
    for (int i = 0; i < 4; i++)
        d[i] = ip->saddr[i];
    key.priv_src_port = tcp->source;

    __u64 *val = bpf_map_lookup_elem(&napt_fwd_44, &key);
    if (val) {
        // Inbound traffic
        struct napt_tuple *rev_key = (__u64 *)val;
        #pragma unroll
        for (int i = 0; i < 4; i++)
            ip->saddr[i] = rev_key->priv_src_ip;
        tcp->source = rev_key->priv_src_port;
        return XDP_PASS;
    }

    // Outbound traffic
    __u32 new_ip = 0x64519851; // 198.51.100.1
    __u16 new_port = 30000;
    #pragma unroll
    for (int i = 0; i < 4; i++)
        ip->saddr[i] = (ip->saddr[i] == 10 && i == 0) ? 198 : 
                       (ip->saddr[i] == 0 && i == 1) ? 51 : 
                       (ip->saddr[i] == 0 && i == 2) ? 100 : ip->saddr[i];
    tcp->source = new_port;

    struct napt_tuple *new_key = &key;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&napt_fwd_44, new_key, &now, BPF_ANY);
    bpf_map_update_elem(&napt_rev_44, new_key, &now, BPF_ANY);
    
    // Recalculate checksum
    __u32 csum = 0;
    ip->check = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++)
        csum += ((__u16 *)ip)[i];
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~csum;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
