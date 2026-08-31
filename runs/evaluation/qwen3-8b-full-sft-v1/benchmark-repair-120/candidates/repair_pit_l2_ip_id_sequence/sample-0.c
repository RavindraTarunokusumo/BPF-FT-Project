#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct ip_key {
    __u32 saddr;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ip_key);
    __type(value, __u16);
    __uint(max_entries, 1024);
} ip_id_map SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    struct ip_key key = {0};
    key.saddr = ip->saddr;

    __u16 id = bpf_ntohs(ip->id);
    __u16 *new_id = bpf_map_lookup_elem(&ip_id_map, &key);
    if (new_id) {
        __u16 next_id = (*new_id + 1) % 65536;
        bpf_map_update_elem(&ip_id_map, &key, &next_id, BPF_ANY);
        return XDP_PASS;
    } else {
        bpf_map_update_elem(&ip_id_map, &key, &id, BPF_ANY);
        return XDP_PASS;
    }
}

char LICENSE[] SEC("license") = "GPL";
